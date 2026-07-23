import subprocess
from . import rewrite_function
from .rewrite_function import FunctionRewriter, Tokenizer, decompile, initialize_ghidra_from_gzf, initialize_ghidra_from_real_project, rewrite_function

def test(addr):
  func = rewrite_function.currentProgram.getFunctionManager().getFunctionAt(rewrite_function.flat_api.toAddr(addr))
  r = decompile(func, "decompile")
  fw = FunctionRewriter(r)
  fnew = fw.rewrite_function(Tokenizer(r.getCCodeMarkup()))

  print("============= OLD ===============")
  print(r.getDecompiledFunction().getC())

  print("============= NEW RAW ===========")
  print(fnew)

  print("============= NEW ===============")
  ps = subprocess.Popen(["clang-format"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
  print(ps.communicate(fnew)[0])

def run_tests():
  #test(0x401000)
  #test(0x00401040)
  #test(0x00401060)
  #test(0x00401620) # handle ADJ() and enum values
  #test(0x004016e0) # Super complex if else statements and member calls
  #test(0x004039b0) # function call without namespace prefix
  test(0x00465700) # Test namespace functions
