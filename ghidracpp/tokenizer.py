from typing import List


try: 
  import typing
  if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import ClangFunction # pyright: ignore[reportMissingModuleSource]
    from ghidra.app.decompiler import ClangStatement # pyright: ignore[reportMissingModuleSource]
    from ghidra.app.decompiler import ClangFuncProto # pyright: ignore[reportMissingModuleSource]
    from ghidra.app.decompiler import ClangFuncNameToken # pyright: ignore[reportMissingModuleSource]
    from ghidra.app.decompiler import ClangTokenGroup # pyright: ignore[reportMissingModuleSource]
    from ghidra.app.decompiler import DecompileResults # pyright: ignore[reportMissingModuleSource]
except:
  pass

def ccodemarkupexporter(result, markup): # pyright: ignore[reportPossiblyUnboundVariable]
  if hasattr(markup, "__iter__"): # pyright: ignore[reportPossiblyUnboundVariable]
    sublist = []
    result.append({
      "cls": markup.__class__.__name__,
      "nodes": sublist,
    })
    for el in markup:
      ccodemarkupexporter(sublist, el)
  else:
    result.append({
      "cls": markup.__class__.__name__,
      "token": markup.toString(),
    })




class Tokenizer(object):

  def __init__(self, ast, start_at_zero = True):
    if not hasattr(ast, "__iter__"):
      raise Exception("AST not iterable. Is it a token?: '" + str(ast) + "'")
    self._ast = ast
    self._tokens = list(ast)
    self._index = -1
    self._start_at_zero = start_at_zero
    if start_at_zero:
      self._index = 0

  def __iter__(self):
    for token in self._tokens:
      yield token

  def __getitem__(self, key):
    return self._tokens[key]
  
  def __repr__(self) -> str:
    if self._index >= 0 and self._index < len(self._tokens):
      upcoming = ', '.join('"' + str(s) + '"' for s in self._tokens[self._index+1:][0:5])
      return 'Tokenizer<current = "' + str(self._tokens[self._index]) + '", class=' + self.class_name(self.current()) +', upcoming=[' + upcoming + ']>'
    return "Tokenizer<current = (" + str(self._index) +")>"
  
  def get_context(self):
    return self.class_name(self._ast)
  
  def reset(self, start_at_zero = None):
    saz = self._start_at_zero if start_at_zero is None else start_at_zero
    if saz:
      self._index = 0
    else:
      self._index = -1
    return self
  
  def tokens(self):
    return self._tokens
  
  def has_token(self, predicate = lambda x: True):
    for tok in self._tokens:
      if predicate(tok):
        return True
    return False
  
  def has_upcoming_token(self,
                         predicate = lambda x: True,
                         failfast = lambda x: False,
                         include_current = False):
    offset = self._index if self._index >= 0 else 0
    if not include_current:
      offset += 1
    for tok in self._tokens[offset:]:
      if failfast(tok):
        return False
      if predicate(tok):
        return True
    return False

  def class_name(self, obj):
    if hasattr(obj, "cls"):
      return obj.cls
    return obj.__class__.__name__.split(".")[-1]
  
  def is_instance(self, obj, name):
    return self.class_name(obj) == name
  
  def current(self):
    if self._index < 0 or self._index >= len(self._tokens):
      raise Exception("invalid index: " + str(self._index))
    return self._tokens[self._index]
  
  def enter(self, start_at_zero = None):
    return Tokenizer(self.current(), self._start_at_zero if start_at_zero is None else start_at_zero)
  
  def has_next(self, n = 1):
    if (self._index + n) >= len(self._tokens):
      return False
    return True
  
  def has_previous(self, n = 1):
    if (self._index - n) < 0:
      return False
    return True
  
  def next(self, no_exception = False):
    if not self.has_next():
      if no_exception:
        return None
      raise Exception("no entries left")
    self._index += 1
    return self._tokens[self._index]
  
  def previous(self, no_exception = False):
    if not self.has_previous():
      if no_exception:
        return None
      raise Exception("no entries left")
    self._index -= 1
    return self._tokens[self._index]
  
  def rewind(self, n = 1):
    self._index -= n
    if self._index < 0:
      self._index = -1

  def forward(self, n = 1):
    self._index += n
    if self._index > len(self._tokens):
      self._index = len(self._tokens) - 1

  def peek(self, n = 1):
    if not self.has_next(n = n):
      return None
    return self._tokens[self._index + n]
  
  def peek_until(self, predicate = lambda x: False, inclusive_return = False):
    peek_result = []
    if not self.has_next():
      return peek_result
    for i in range(self._index + 1, len(self._tokens), 1):
      peek_token = self._tokens[i]
      if predicate(peek_token):
        if inclusive_return:
          peek_result.append(peek_token)
        return peek_result
      peek_result.append(peek_token)
    return peek_result
  
  def look_back_until(self, predicate = lambda x: True, inclusive_return = False):
    tail_result = []
    if self._index < 1:
      return tail_result
    for i in range(self._index - 1, -1, -1):
      tail_token = self._tokens[i]
      if predicate(tail_token):
        if inclusive_return:
          tail_result.insert(0, tail_token)
        return tail_result
      tail_result.insert(0, tail_token)
    return tail_result
  
  def advance_multiple(self, n = 1, no_exception = False):
    return [self.next(no_exception = no_exception) for i in range(n)]
  
  def advance_until(self, predicate = lambda x: False, inclusive_return = False):
    """
    @param including bool only affects whether it is included in the result or not, not whether the advance actually includes it...
    """
    advance_result = []
    while self.has_next():
      n = self.next()
      if predicate(n):
        if inclusive_return:
          advance_result.append(n)
        return advance_result
      advance_result.append(n)
    return advance_result
  
  def rewind_until(self, predicate = lambda x: False, inclusive_return = False):
    rewind_result = []
    while self.has_previous():
      n = self.previous()
      if predicate(n):
        if inclusive_return:
          rewind_result.insert(0, n)
        return rewind_result
      rewind_result.insert(0, n)
    return rewind_result
  
  @staticmethod
  def _test():
    TEST_1 = list(range(0, 10, 1))
    TEST_1.insert(3, list(range(11, 20, 1))) # type: ignore
    t1 = Tokenizer(TEST_1)
    peeked_obj = t1.peek_until(lambda x: isinstance(x, list))
    l = t1.peek(len(peeked_obj) + 1)
    if not isinstance(l, list):
      raise Exception()
    forward_objs = t1.advance_until(lambda x: isinstance(x, list), inclusive_return=True)
    if not l == forward_objs[-1]:
      raise Exception()
    if not l == t1.current():
      raise Exception()
    backtracked_objs = t1.rewind_until(lambda x: x == forward_objs[0], inclusive_return=True)
    if not backtracked_objs == forward_objs[:-1]:
      raise Exception()
    t1.advance_until(lambda x: isinstance(x, list), inclusive_return=False)
    t2 = t1.enter()
    if not t2._tokens == list(range(11, 20, 1)):
      raise Exception()

if __name__ == "__main__":
  Tokenizer._test()