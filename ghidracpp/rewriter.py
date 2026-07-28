from collections.abc import Iterable
import re
import sys
from typing import Dict, List, Set

from .tokenizer import Tokenizer

from ghidra.app.decompiler import ClangCaseToken, ClangFieldToken, ClangFuncNameToken, ClangOpToken, ClangTypeToken, ClangVariableToken, DecompileResults
from ghidra.program.model.pcode import EquateSymbol, HighConstant, HighFunction
from ghidra.program.model.listing import Function
from ghidra.program.model.data import Array, DataType, Structure, TypeDef, Pointer, Enum

def joinit(iterable, delimiter):
    try:
        it = iter(iterable)
        yield next(it)
        for x in it:
            yield delimiter
            yield x
    except StopIteration:
        return

class FunctionRewriter(object):

  def __init__(self, results: DecompileResults) -> None:
    self._results = results
    self._hf: HighFunction = results.getHighFunction()
    self._namespace = list(str(n) for n in self._results.getFunction().getParentNamespace().getPathList(True))
    self._wrapping_namespace = self._namespace[:-1]
    self._namespace_type = self._results.getFunction().getParentNamespace().getType().name()
    self._global_symbols = dict((s.getName(), s) for s in self._hf.getGlobalSymbolMap().getSymbols())
    self._includes = [f'/{"/".join(self._namespace)}.func'] #.func by default
    self._usings = []
    self._program = self._hf.getDataTypeManager().getProgram()
    # Entity * 40 psVar1;
    # psVar1 = &this->entityArray[1].logicalState;
    # Should become:
    # Entity psvar1;
    # psVar1 = &this->entityArray[1];
    # This properly resolves the ADJ()
    self._zap_field_for_symbol: Dict[str, DataType] = {}
    for symbol in self._hf.getLocalSymbolMap().getSymbols():
      dt = symbol.getDataType()
      if isinstance(dt, TypeDef):
        td: TypeDef = dt
        if td.isPointer():
          bdt = td.getBaseDataType()
          if isinstance(bdt, Pointer):
            odt = bdt.getDataType()
            self.register_datatype(odt, usings=True)
            self._zap_field_for_symbol[symbol.getName()] = odt
    self._returnType = self._results.getFunction().getReturnType()

  def var_path_matches_namespace(self, path: str):
    ns = [el for el in path.split("/") if el]
    return ns == self._namespace

  def is_this_variable(self, tok: ClangVariableToken):
    """Returns if the token's high symbol has a data type that has the name path as the function's namespace"""
    hs = tok.getHighSymbol(self._hf)
    if not hs:
      return False
    if not hs.isGlobal():
      return False
    dt = hs.getDataType()
    return self.var_path_matches_namespace(str(dt.getDataTypePath()))

  def register_datatype(self, dt, usings = False, ignore_simple: bool = True):
    include = str(dt.getDataTypePath())
    if ignore_simple:
      if not include.startswith("/_HoldStrong"):
        return
    if not include in self._includes:
      self._includes.append(include)
    if usings and not include in self._usings:
      self._usings.append(include)

  def register_enum(self, dt: Enum, key: str):
    include = str(dt.getDataTypePath())
    if include.endswith("Byte"):
      include = include[:-4]
    elif include.endswith("Short"):
      include = include[:-5]
    elif include.endswith("Int"):
      include = include[:-3]
    if not include in self._includes:
      self._includes.append(include)
    #using = str(dt.getDataTypePath().getCategoryPath()) # Doesn't work
    using = include
    if using not in self._usings:
      self._usings.append(using)
    if False:
      # This doesn't work because our MSVC doesn't support it
      using = f"{include}/{key}"
      if using not in self._usings:
        self._usings.append(using)

  def rewrite_ClangTypeToken(self, tok: ClangTypeToken):
    dt = tok.getDataType()
    if isinstance(dt, TypeDef):
      td: TypeDef = dt
      if td.isPointer():
        bdt = td.getBaseDataType()
        if isinstance(bdt, Pointer):
          odt = bdt.getDataType()
          self.register_datatype(odt, usings=True)
          return [f"{odt.getName()} *"]
    self.register_datatype(dt, usings=True)
    return [str(tok)]

  def rewrite_ClangVariableDecl(self, cvd: Tokenizer):
    # assert cvd.has_next()
    r = []
    ctt = cvd.next()
    if not isinstance(ctt, ClangTypeToken):
      raise Exception(f"unexpected tokens: {cvd._tokens}")
    r += self.rewrite_current(cvd) # Convert Short, Byte and Int enums to their parent?
    while cvd.has_next():
      cur = cvd.next()
      if isinstance(cur, ClangVariableToken):
        r.append(str(cur))
      else:
        r += self.rewrite_current(cvd)
    # while cvd.has_next():
    #   cvd.next()
    #   r += self.rewrite_current(cvd)
    return r

  def rewrite_ClangFuncProto_ClangReturnType(self, crt: Tokenizer):
    assert crt.has_next()
    tok = crt.next()
    dt = tok.getDataType() # type: ignore
    self.register_datatype(dt, usings=True)
    r = [dt.getName()]
    while crt.has_next():
      crt.next()
      r += self.rewrite_current(crt)
    return r

  def rewrite_ClangFuncProto_ClangVariableDecl(self, cvd: Tokenizer):
    assert cvd.has_next()
    if cvd.has_upcoming_token(lambda x: str(x) == "this"):
      return [] # We swallow ClassType * this
    
    tok_dt = cvd.next()
    dt = tok_dt.getDataType() # type: ignore
    self.register_datatype(dt, usings=True)

    return [str(tok) for tok in cvd._tokens]

  def rewrite_ClangFuncProto(self, cfp: Tokenizer):
    r = [f"// FUNCTION: STRONGHOLDCRUSADER {'0x{:08X}'.format(self._results.getFunction().getEntryPoint().getOffset())}", "\n"]
    while cfp.has_next():
      tok = cfp.next()
      cc = self._results.getFunction().getCallingConvention().getName()
      if str(tok) == cc or str(tok) == self._namespace[0]:
        if str(tok) == cc and not str(tok).startswith("__thiscall"): # swallows __thiscall_noECXClobber etc.
          r.append(str(tok))
        elif str(tok) == self._namespace[0]:
          # No calling convention specified, inject
          r += [str(cc), " "]
        # After parsing the calling convention we are guaranteed going to enter the function name(space)
        r += [self._namespace[-1], " :: ", self._results.getFunction().getName()]
        while str(cfp.current()) != "(":
          tok = cfp.next()
        r.append("(")
        params = []
        while cfp.has_next():
          cfp.next()
          if cfp.class_name(cfp.current()) == "ClangVariableDecl":
            param = self.rewrite_current(cfp, ["ClangFuncProto"])
            if param:
              params.append(''.join(param))
        r += list(joinit(params, ','))
        r.append(")")
        return r
      r += self.rewrite_current(cfp, ["ClangFuncProto"])  
    return r
  
  def is_thiscall(self, token):
    pass

  def rewrite_variable_only(self, v):
    return v.token + "::instance"
  
  def rewrite_variable(self, v: Tokenizer):
    r = []
    if v.is_instance(v.current(), "ClangOpToken") and str(v.current()) == "&":
      if v.is_instance(v.peek(2), "ClangVariableToken"):
        t4s = str(v.peek(4))
        if t4s == ".":
          r += ["&", str(v.peek(2)), "::instance", "."]
        else:
          r += [str(v.peek(2)), "::instance"]
        v.forward(4)
    elif v.is_instance(v.current(), "ClangVariableToken"):
      if str(v.peek(1)) == ".":
        r += [str(v.current()) + "::instance", "."]
      else:
        r += [str(v.current()) + "::instance"]
    return r
  
  def _process_first_method_argument(self, fn: Tokenizer):
    assert str(fn.peek(2)) == "("
    r = []
    if str(fn.peek(4)) == "this":
      fn.advance_multiple(4)
      return ["this"]
    if str(fn.peek(4)) == "&":
      var = fn.advance_multiple(6)[-1]
      if isinstance(var, ClangVariableToken) and self.is_this_variable(var):
        return ["this"]
      return [f"{var}::ptr"]
    else:
      tok = fn.peek(4)
      if isinstance(tok, ClangVariableToken):
        hs = tok.getHighSymbol(self._hf)
        if not hs.isGlobal():
          return [fn.advance_multiple(4)[-1]]
      else:
        print(f"unexpected function argument: {self._hf.getFunction()}: {fn._tokens}", file=sys.stderr)
    return [fn.advance_multiple(4)[-1]]
  
  def _process_func_args(self, fn: Tokenizer, brace_method: bool = True, brace_depth = 1, arg_types: List[DataType] = []):
    r = []
    if not brace_method:
      while fn.has_next() and fn.has_upcoming_token(predicate=lambda x: True, failfast=lambda x: str(x) in [")", ";"]):
        # TODO: how to handle end of arguments of function??
        fn.next()
        r += self.rewrite_current(fn)
      if str(fn.peek()) == ")":
        fn.next()
      return r

    r += self.rewrite_function_brace_contents(fn, brace_depth=brace_depth, arg_types=arg_types)
    return r

  def rewrite_function_namespace(self, fn: Tokenizer):
    r = []
    f = [fn.current()]
    if fn.class_name(fn.current()) != "ClangFuncNameToken":
      f += fn.advance_until(lambda x: fn.is_instance(x, "ClangFuncNameToken"), inclusive_return=True)
    # current() is now the function name
    if f:
      funcname = f[-1]
      if not isinstance(funcname, ClangFuncNameToken):
        raise Exception()

      addr = funcname.getMinAddress()
      cu = self._program.getListing().getCodeUnitAt(addr)
      if cu.getMnemonicString() != "CALL" and cu.getMnemonicString() != "JMP":
        raise Exception(addr)
      target_address = cu.getPrimaryReference(0).getToAddress()
      cuf = self._program.getListing().getCodeUnitAt(target_address)
      if cuf.getMnemonicString() == "addr":
        # function is a thunk situation, basically call dword ptr[addr]
        return [funcname]
      func: Function = self._program.getFunctionManager().getFunctionAt(target_address)
      pns = func.getParentNamespace()
      pl = list(pns.getPathList(True))
      pli = [str(n) for n in pl[:-1]] + [f"{pl[-1]}.func"]
      inc = f"/{'/'.join(pli)}"
      if inc not in self._includes:
        self._includes.append(inc)
      plf = [str(n) for n in pl[:-1]] + [f"{pl[-1]}_Func"]
      pl_func = "::".join(plf) # type: ignore
      pl_func += "::" + func.getName()
      if pns.getType().name() == "CLASS":
        first = self._process_first_method_argument(fn)
        args = []
        # Test if it has another argument
        if str(fn.peek(2)) == ",":
          fn.advance_multiple(2)
          args = self._process_func_args(fn, arg_types=[param.getDataType() for param in func.getParameters() if param.getName() != "this"])
        elif str(fn.peek(2)) == ")":
          fn.advance_multiple(2)
        r +=  [
          "MACRO_CALL_MEMBER",
          "(",
          pl_func,
          ",",
          " ",
          *first,
          ")",
          "(",
          *args,
          ")",
        ]
      else:
        # TODO:
        # We are now at the function argument, we expect a "(" in 2
        assert str(fn.peek(2)) == "("
        fn.advance_multiple(2)
        args = self._process_func_args(fn,brace_depth=0, arg_types=[param.getDataType() for param in func.getParameters() if param.getName() != "this"]) # Set to 0 because we are sitting on "("
        r += [
          "MACRO_CALL",
          "(",
          pl_func,
          ")",
          "(",
          *args,
          ")",
        ]
    else:
      funcname = fn.current()
      r.append(funcname)
    return r
  
  def singleton_symbol(self):
    return None
  
  def sanitize_enum_name(self, n: str):
    for suffix in ["Int", "Short", "Byte"]:
      if n.endswith(suffix):
        return n[:-len(suffix)]
    return n

  def peek_at_final_datatype(self, t: Tokenizer, no_array_resolving = False):
    # Tokenizer should be a finite tokens list
    remaining = t.peek_until(lambda x: False, inclusive_return=True)
    s = Tokenizer(remaining, start_at_zero=False)
    last_seen_type = None
    brace_depth = 0
    array_depth = 0
    while s.has_next():
      cur = s.next()
      cur_str = str(cur)
      if cur_str == "(":
        brace_depth += 1
      elif cur_str == ")":
        brace_depth -= 1
      elif cur_str == "[":
        array_depth += 1
      elif cur_str == "]":
        array_depth -= 1
      if array_depth == 0 and isinstance(cur, ClangVariableToken):
        hs = cur.getHighSymbol(self._hf)
        if hs:
          dt = hs.getDataType()
          if dt:
            last_seen_type = dt
        else:
          hv = cur.getHighVariable()
          if hv:
            dt = hv.getDataType()
            if dt:
              last_seen_type = dt
      elif array_depth == 0 and isinstance(cur, ClangFieldToken):
        cdt = cur.getDataType() # container type
        if isinstance(cdt, Structure):
          comp = cdt.getComponentAt(cur.getOffset())
          fn = comp.getFieldName() or comp.getDefaultFieldName()
          assert fn == str(cur)
          last_seen_type = comp.getDataType()
        else:
          hs = cur.getHighSymbol(self._hf)
          if hs:
            dt = hs.getDataType()
            if dt:
              last_seen_type = dt
    while isinstance(last_seen_type, Array):
      last_seen_type = last_seen_type.getDataType()
    return last_seen_type

  def split_brace_contents(self, t: Tokenizer, separator: str = ",", brace_depth: int = 0):
    s = Tokenizer(t.peek_until(lambda x: False, inclusive_return=True, include_current=True), start_at_zero=True)
    if str(s.current()) == "(":
      brace_depth += 1
    if brace_depth == 0:
      raise Exception("won't start alg, brace_depth == 0")
    array_depth = 0
    parts = []
    part = []
    while brace_depth > 0 and s.has_upcoming_token(lambda x: str(x) == ")", include_current=True):
      if not s.has_next():
        raise Exception("unclosed brace")
      cur = s.next()
      cur_str = str(cur)
      if cur_str == "(":
        brace_depth += 1
      elif cur_str == ")":
        brace_depth -= 1
      elif cur_str == "[":
        array_depth += 1
      elif cur_str == "]":
        array_depth -= 1
      if brace_depth == 0:
        parts.append(part.copy())
        part.clear()
        return parts
      if array_depth == 0 and cur_str == separator:
        parts.append(part.copy())
        part.clear()
        # Swallow the separator
      else:
        part.append(cur)
    return parts

  def rewrite_function_brace_contents(self, s: Tokenizer, brace_depth: int = 0, arg_types: List[DataType] = []):
    r = []
    if str(s.current()) == "(":
      brace_depth += 1
    if brace_depth == 0:
      raise Exception("won't start alg, brace_depth == 0")
    array_depth = 0
    arg_i = 0
    expected_type: DataType | None = None
    last_seen_type: DataType | None = None
    arg_part = []
    while brace_depth > 0 and s.has_upcoming_token(lambda x: str(x) == ")"):
      if not s.has_next():
        raise Exception("unclosed brace")
      cur = s.next()
      cur_str = str(cur)
      if cur_str == "(":
        brace_depth += 1
      elif cur_str == ")":
        brace_depth -= 1
      elif cur_str == "[":
        array_depth += 1
      elif cur_str == "]":
        array_depth -= 1
      if brace_depth == 0:
        if last_seen_type != expected_type and last_seen_type is not None and expected_type is not None:
          self.register_datatype(expected_type, usings=True)
          en = expected_type.getName()
          if isinstance(expected_type, Enum):
            en = self.sanitize_enum_name(expected_type.getDataTypePath().getDataTypeName())
          tcast = f"({en})"
          arg_part_string = "".join(str(a) for a in arg_part)
          # Remove direct casts to this type as they often fail, instead, cast to int first
          arg_part_string = arg_part_string.replace(tcast, "")
          arg_part = [f"{tcast}((int)", "("] + [arg_part_string] + ["))"] # (int) is dubious here!
        r += arg_part
        return r
      
      if cur_str == ",":
        # Assumes commas are proper separators for arguments
        if last_seen_type != expected_type and last_seen_type is not None and expected_type is not None:
          self.register_datatype(expected_type, usings=True)
          tcast = f"({expected_type.getName()})"
          arg_part_string = "".join(arg_part)
          # Remove direct casts to this type as they often fail, instead, cast to int first
          arg_part_string = arg_part_string.replace(tcast, "")
          arg_part = [f"{tcast}((int)", "("] + [arg_part_string] + ["))"]
        r += arg_part + [",", " "]
        arg_part.clear()
        arg_i += 1
        if arg_types:
          if not arg_i < len(arg_types):
            last_seen_type = None # reset
            expected_type = None
          else:
            expected_type = arg_types[arg_i]
            last_seen_type = None # reset
        continue
      if array_depth == 0 and isinstance(cur, ClangVariableToken):
        hs = cur.getHighSymbol(self._hf)
        if hs:
          dt = hs.getDataType()
          if dt:
            last_seen_type = dt
      elif array_depth == 0 and isinstance(cur, ClangFieldToken):
        cdt = cur.getDataType() # container type
        if isinstance(cdt, Structure):
          comp = cdt.getComponentAt(cur.getOffset())
          fn = comp.getFieldName() or comp.getDefaultFieldName()
          assert fn == str(cur)
          last_seen_type = comp.getDataType()
        else:
          hs = cur.getHighSymbol(self._hf)
          if hs:
            dt = hs.getDataType()
            if dt:
              last_seen_type = dt
      if str(cur) == "&" and s.class_name(s.peek(2)) == "ClangVariableToken":
        arg_part += self.rewrite_ampersand_var_optional_accessor(s)
      elif isinstance(cur, ClangVariableToken):
        if self.is_this_variable(cur):
          arg_part.append("this")
          if str(s.peek(2)) == ".": #s.advance_until(lambda x: s.class_name(x) != "ClangBreak" and str(s) != " ")
          #if str(s.next()) == ".":
            arg_part.append("->") # substitute . with -> in case of DAT_ to this conversion
            s.advance_multiple(2)
        elif cur.getHighSymbol(self._hf) and cur.getHighSymbol(self._hf).isGlobal():
          arg_part += [f"{cur}::instance"]
        else:
          arg_part += self.rewrite_current(s)
      else:
        arg_part += self.rewrite_current(s)
    return r

  
  def rewrite_ClangStatement(self, s: Tokenizer):
    r = []
    zap_fields = False
    zap_after_data_type: DataType | None = None
    # expected_rhs_data_type: DataType | None = None
    while s.has_next():
      s.next()
      cur = s.current()
      if str(cur) == "&" and s.class_name(s.peek(2)) == "ClangVariableToken":
        r += self.rewrite_ampersand_var_optional_accessor(s)
      elif s.class_name(cur) == "ClangVariableToken":
        if zap_after_data_type and isinstance(cur, ClangVariableToken):
          hs = cur.getHighSymbol(self._hf)
          if hs:
            if hs.isGlobal() and s.has_upcoming_token(lambda x: str(x) == "+"):
              # TODO: this is basically guess work of what the rest of the statement looks like
              # _ptrCurrentGold = (PlayerData *)(& DAT_GameState::instance.playerDataArray[1] + 0xf);
              r += ["&"]
        if self.is_this_variable(cur):
          r.append("this")
          if s.has_upcoming_token(lambda x: s.class_name(x) != "ClangBreak" and str(s) != " "):
            s.advance_until(lambda x: s.class_name(x) != "ClangBreak" and str(s) != " ")
            if str(s.next()) == ".":
              r.append("->") # substitute . with -> in case of DAT_ to this conversion
              s.next()
        elif cur.getHighSymbol(self._hf) and cur.getHighSymbol(self._hf).isGlobal():
          r += [f"{cur}::instance"]
        elif str(cur) in self._zap_field_for_symbol:
          zap_after_data_type = self._zap_field_for_symbol[str(cur)]
          r += self.rewrite_current(s, context=["ClangStatement"])
        # elif s.has_upcoming_token(lambda x: str(x) == "="):
        #   # Assignment statement
        #   expected_rhs_data_type = cur.getHighSymbol(self._hf).getDataType() if cur.getHighSymbol(self._hf) else None
        #   if expected_rhs_data_type:
        #     rhs = self.peek_at_final_datatype(s)
        #     if rhs:
        #       if expected_rhs_data_type == rhs:
        #         # Signals no cast is necessary
        #         expected_rhs_data_type = None
        #     else:
        #       expected_rhs_data_type = None
        #   r += self.rewrite_current(s, context=["ClangStatement"])
        else:
          r += self.rewrite_current(s, context=["ClangStatement"])
      elif zap_fields and str(cur) == ".":
        s.advance_multiple(2) # zap!
      # elif expected_rhs_data_type and str(cur) == "=":
      #   r += self.rewrite_current(s, context=["ClangStatement"])
      #   tn = self.sanitize_enum_name(expected_rhs_data_type.getName())
      #   cast = f"({tn})"
      #   if cast not in str(s._tokens) and cast not in ''.join(str(t) for t in s._tokens):
      #     r += ["(", tn, ")"] # Inject cast
      elif s.has_upcoming_token(
                      predicate=lambda x: s.is_instance(x, "ClangFuncNameToken"),
                      failfast=lambda x: re.match(pattern="([^A-Za-z0-9_:]*)",
                                                      string=str(x)).group(0), # type: ignore
                      include_current=True):
        if "__security_check_cookie" in str(s._tokens):
          return []
        # Note this inherits the Tokenizer instead of entering a new situation
        r += self.rewrite_function_namespace(s)
      elif s.class_name(cur) == "ClangOpToken" and str(cur) == "ADJ":
        assert str(s.peek(2)) == "("
        s.advance_multiple(2)
        r += self.rewrite_function_brace_contents(s)
        assert str(s.current()) == ")"
        # swallow the ")"
      elif s.class_name(cur) == "ClangOpToken" and str(cur).startswith("SBORROW"):
        assert str(s.peek(2)) == "("
        s.advance_multiple(2)
        a, b = self.split_brace_contents(s)
        s.advance_until(lambda x: x == b[-1])
        s.next()
        #s.advance_multiple(len(a) + len(b) + 1)
        r += ["("] + self.rewrite_ClangStatement(Tokenizer(a, start_at_zero=False)) + [" ", "<", " "] + self.rewrite_ClangStatement(Tokenizer(b, start_at_zero=False)) + [")"]
      elif zap_after_data_type and s.has_next(4) and isinstance(s.peek(4), ClangFieldToken):
        # We are about to do .subfield
        tok = s.peek(4)
        if not isinstance(tok, ClangFieldToken):
          raise Exception()
        if tok.getDataType() == zap_after_data_type:
          r += self.rewrite_current(s, context=["ClangStatement"])
          if str(s.peek(6)) == "+" and str(s.peek(8) != ""):
            s.advance_multiple(8) # super  zap:     _ptrCurrentGold = (PlayerData *)(DAT_GameState::instance.playerDataArray[1] + 0xf);
          else:
            s.advance_multiple(4)  # zap!
          zap_fields = True # keep zapping fields!
        else:
          r += self.rewrite_current(s, context=["ClangStatement"])
      elif s.class_name(cur) == "ClangOpToken" and str(cur) == "return" and s.class_name(s.peek(2)) == "ClangVariableToken":
        expectedReturnType = self._returnType
        observedReturnType = self.peek_at_final_datatype(s, no_array_resolving=isinstance(expectedReturnType, Array))
        if expectedReturnType != observedReturnType and expectedReturnType is not None and observedReturnType is not None:
          r += [cur, "(", expectedReturnType.getName(), ")", "("]
          r += self.rewrite_ClangStatement(s) # recursion
          r += [")"]
        else:
          r += self.rewrite_current(s, context=["ClangStatement"])
      else:
        r += self.rewrite_current(s, context=["ClangStatement"])
    return r
  
  def rewrite_ClangVariableToken(self, cvt: ClangVariableToken):
    hs = cvt.getHighSymbol(self._hf)
    if isinstance(hs, EquateSymbol):
      if not hs.getDataType() or str(hs.getDataType()) == 'undefined':
        return [str(hs.getValue())] # We do this because we can't get the enum associated with the equate name from anywhere...
      self.register_datatype(hs.getDataType(), usings = True)
    hc = cvt.getHighVariable()
    if isinstance(hc, HighConstant): # As opposed to a HighLocal which is a variable name
      dt = hc.getDataType()
      if isinstance(dt, Enum):
        self.register_enum(dt, str(cvt))
        if hc.getDataType().getName() == "BOOLEnum":
          return [str(cvt)] # TRUE and FALSE can be written as such
        return self.properly_name_enum(dt, cvt)
    # if str(cvt) == "'\\0'":
    #   return [str(0)] # convert uchar and char 0's into proper decimal 0's
    return [str(cvt)]
  
  def properly_name_enum(self, dt: Enum, cvt: ClangVariableToken | ClangCaseToken):
    if re.match("^[0-9]+$", str(cvt)) or re.match("^0x[0-9]+$", str(cvt)):
      # cast const enums to enum type
      return ["(", "(", self.sanitize_enum_name(dt.getDataTypePath().getDataTypeName()), ")", str(cvt), ")"]
    dtp = dt.getCategoryPath().getPath()
    dtns = dtp[1:].replace("/", "::")
    return [f'{dtns}::{str(cvt)}']

  def rewrite_ClangOpToken(self, tok: ClangOpToken):
    return [str(tok)]

  def rewrite_ClangBreak(self):
    return ["\n"]
  
  def rewrite_ampersand_var_optional_accessor(self, s: Tokenizer):
    # "&DAT_global." and &DAT_global +" and "&DAT_global,"
    r = []
    cur = s.current()
    assert str(cur) == "&"
    assert s.class_name(s.peek(2)) == "ClangVariableToken"
    var = s.peek(2)
    assert isinstance(var, ClangVariableToken)

    hs = var.getHighSymbol(self._hf)
    isGlobal = hs and hs.isGlobal()
    accessor = s.peek(4)
    if str(accessor) == ".":
      if isGlobal:
        if self.is_this_variable(var):
          r += [cur, "this", "->"]
        else:
          r += [cur, var, "::instance", accessor]
      else:
        r += [cur, var, accessor]
      s.advance_multiple(4)
    else:  
      if isGlobal:
        if self.is_this_variable(var):
          r += ["this"]
        else:
          r += [var, "::ptr"]
      else:
        r += [cur, var]
      s.advance_multiple(2)
    return r
  
  def rewrite_ClangCaseToken(self, t: ClangCaseToken):
    dt: DataType | None = None
    hs = t.getHighSymbol(self._hf)
    if not hs:
      hv = t.getHighVariable()
      if hv:
        dt = hv.getDataType()
    else:
      dt = hs.getDataType()
    if dt:
      if isinstance(dt, Enum):
        return self.properly_name_enum(dt, t)
    return [str(t)]

  def rewrite_ClangTokenGroup(self, s: Tokenizer):
    s.reset(False)
    r = []
    while s.has_next():
      s.next()
      cur = s.current()
      if str(cur) == "&" and s.class_name(s.peek(2)) == "ClangVariableToken":
        r += self.rewrite_ampersand_var_optional_accessor(s)
      elif s.class_name(cur) == "ClangVariableToken":
        if self.is_this_variable(cur):
          r.append("this")
          s.advance_until(lambda x: s.class_name(x) != "ClangBreak" and str(s) != " ")
          if str(s.next()) == ".":
            r.append("->") # substitute . with -> in case of DAT_ to this conversion
            s.next()
        elif cur.getHighSymbol(self._hf) and cur.getHighSymbol(self._hf).isGlobal():
          r += [f"{cur}::instance"]
        else:
          r += self.rewrite_current(s)
      else:
        r += self.rewrite_current(s)
    return r
  
  def rewrite_current(self,
                      s: Tokenizer,
                      context: List[str] = [],
                      fallback: bool = True):
    r = []
    cur = s.current()
    n = s.class_name(cur)
    simple_needle = f"rewrite_{n}"
    needle = simple_needle
    if context:
      needle = f"rewrite_{'_'.join(context)}_{n}"
    if n == "ClangBreak":
      r += self.rewrite_ClangBreak()
    elif n == "ClangOpToken" and str(cur) == "ADJ":
      s.advance_multiple(2) # Swallow ADJ, insert contents between ()
      r += self.rewrite_function_brace_contents(s)
    elif hasattr(self, needle):
      if isinstance(cur, Iterable):
        r += getattr(self, needle)(s.enter(False))
      else:
        r += getattr(self, needle)(cur)
    elif fallback and hasattr(self, simple_needle):
      if isinstance(cur, Iterable):
        r += getattr(self, simple_needle)(s.enter(False))
      else:
        r += getattr(self, simple_needle)(cur)
    else:
      r.append(str(cur))
    return r
  
  def rewrite_function(self, s: Tokenizer):
    r = []
    if s._index == -1:
      s.next()
    while True:
      r += self.rewrite_current(s)
      if not s.has_next():
        break
      s.next()
    indentation = 0
    pr = []
    for c in r:
      newline = False
      newline_before = False
      if str(c) in ["{", "/*", "/**", "/* ", "/** "]:
        indentation += 2
        newline = True
      elif str(c) in ["}", "*/", " */"]:
        indentation -= 2
        newline = True
      elif str(c) in [";"]:
        newline = True
      pr.append(str(c))
      if newline:
        pr.append("\n")      
        if indentation:
          pr.append(" " * indentation)
    includes = "\n".join(f'#include "{str(incl)[1:]}.hpp"' for incl in self._includes)
    wrapper_open = "\n".join(f"namespace {ns} {{" for ns in self._wrapping_namespace)
    wrapper_close = "\n".join(f"}}" for ns in self._wrapping_namespace)
    usings = "\n".join(f'using {"::".join(str(u)[1:].split("/"))};' for u in self._usings)
    global_vars = "\n".join(f'#include "OpenSHC/Globals/{n}.hpp"' for n, s in self._global_symbols.items() if not self.var_path_matches_namespace(str(s.getDataType().getDataTypePath())))
    
    return f"{includes}\n\n{global_vars}\n\n{wrapper_open}\n\n{usings}\n\n{''.join(str(c) for c in pr)}\n\n{wrapper_close}".replace("_HoldStrong", "OpenSHC")