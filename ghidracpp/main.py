
from ghidracpp.test import run_tests

from . import rewrite_function
from .rewrite_function import FunctionRewriter, Tokenizer, decompile, initialize_ghidra_from_gzf, initialize_ghidra_from_real_project
from .rewrite_function import rewrite_function as rw


import argparse, pathlib, sys

parser = argparse.ArgumentParser()
parser.add_argument("--gzf", default="")
parser.add_argument("--project-dir", default="")
parser.add_argument("--project-name", default="")
parser.add_argument("--function", type=str, required=False)
parser.add_argument("--namespace", type=str, required=False)
parser.add_argument("--namespace-output-dir", type=str, required=False)
parser.add_argument("--overwrite", action='store_true', required=False)
parser.add_argument("--namespace-replace", type=str, required=False, default="|")
parser.add_argument("--stdout", action='store_true', default=False)
parser.add_argument("--tests", action='store_true', default=False)

def main():
  args = parser.parse_args()
  if not args.gzf and not args.project_dir and not args.project_name:
    raise Exception(f"invalid arguments: specify --gzf <path> or --project-dir <dir> and --project-name <name>")
  if args.gzf:
    initialize_ghidra_from_gzf(args.gzf)
  elif args.project_name:
    dir = pathlib.Path(args.project_dir or ".").resolve().absolute()
    initialize_ghidra_from_real_project(str(dir), args.project_name)
  if args.tests:
    run_tests()
    import sys
    sys.exit(0)
  if not args.function and not args.namespace:
    raise Exception("must specify either --function <addr of full name> or --namespace <namespace>")
  if args.function:
    print(rw(args.function))
  elif args.namespace:
    odir = pathlib.Path(args.namespace_output_dir or ".")
    fm = rewrite_function.currentProgram.getFunctionManager()
    known_functions = [('::'.join(f.getPathList(True)[:-1]).replace(*args.namespace_replace.split("|")), f,) for f in fm.getFunctions(True)]
    for pns, f in known_functions:
      if pns == args.namespace:
        name = f.getName()
        fp = (odir / f"{name}.cpp")
        if not fp.exists() or args.overwrite:
          (odir / f"{name}.cpp").write_text(data=rw(f), encoding='utf-8')
  

    
    