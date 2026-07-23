import atexit
import tempfile
import pyghidra

from ghidra.base.project import GhidraProject
from ghidra.app.util.importer import ProgramLoader
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.flatapi import FlatProgramAPI

from urllib.parse import urlparse, parse_qs
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults # type: ignore
from ghidra.util.task import ConsoleTaskMonitor # type: ignore
from ghidra.program.model.listing import Function # type: ignore
from ghidra.program.model.pcode import HighSymbol # type: ignore


from .rewriter import FunctionRewriter
from .tokenizer import Tokenizer
import subprocess

import sys

monitor = ConsoleTaskMonitor()

def is_initialized():
  global currentProgram
  if currentProgram is not None:
    return True

def initialize_ghidra_from_real_project(projectDir: str, projectName: str):
  global project
  project = pyghidra.open_project(projectDir, projectName, False)

  global currentProgram
  currentProgram, obj = pyghidra.consume_program(project, "/Stronghold Crusader.exe", project)

  global flat_api
  flat_api = FlatProgramAPI(currentProgram, pyghidra.task_monitor())

def initialize_ghidra_from_gzf(gzfPath: str = "Stronghold Crusader.exe.gzf"):
  project_dir = tempfile.mkdtemp(prefix="ghidra-project-")
  project_name = "temp-project"

  global project
  project = pyghidra.open_project(project_dir, project_name, True)
  loader = pyghidra.program_loader().project(project)
  #fh = File(gzfPath, "rb")
  loader = loader.source(gzfPath)
  with loader.load() as load_results:
    load_results.save(pyghidra.task_monitor()) # type: ignore
  
  global currentProgram
  currentProgram, obj = pyghidra.consume_program(project, "/Stronghold Crusader.exe", project)

  global flat_api
  flat_api = FlatProgramAPI(currentProgram, pyghidra.task_monitor())

def getCurrentProgram():
  return currentProgram

def do_atexit():
  try:
    currentProgram.release(project) # type: ignore
    project.close()
  except:
    pass

atexit.register(do_atexit)

def decompile(func: Function, style = "decompile"):
   # Initialize decompiler
  decompiler = DecompInterface()
  
  # Set decompiler options
  options = DecompileOptions()
  decompiler.setOptions(options)
  
  decompiler.toggleSyntaxTree(True)
  decompiler.toggleCCode(True)
  decompiler.toggleJumpLoads(True)
  decompiler.toggleParamMeasures(True)
  decompiler.setSimplificationStyle(style)
  
  decompiler.openProgram(getCurrentProgram())

  # Decompile
  monitor = ConsoleTaskMonitor()
  results = decompiler.decompileFunction(func, 30, monitor)  # 30 second timeout

  decompiler.closeProgram()

  return results

def rewrite(func: Function):
  r = decompile(func, "decompile")
  fw = FunctionRewriter(r)
  fnew = fw.rewrite_function(Tokenizer(r.getCCodeMarkup()))

  ps = subprocess.Popen(["clang-format"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
  fnew_formatted = ps.communicate(fnew)[0]
  return fnew_formatted

def rewrite_function(function: str | Function):
  if isinstance(function, Function):
    return rewrite(func=function)
  if "::" in function:
    for f in currentProgram.getFunctionManager().getFunctions(True):
      key = f"{'::'.join(str(p) for p in f.getPathList(True))}".replace("_HoldStrong", "OpenSHC")
      if key == function:
        return rewrite(f)
    else:
      raise Exception(f"could not find function: {function}")
  else:
    try:
      addr = int(function, 16)
      func = currentProgram.getFunctionManager().getFunctionAt(flat_api.toAddr(addr))
      return rewrite(func)
    except ValueError:
      raise Exception("invalid hex address: {function}")