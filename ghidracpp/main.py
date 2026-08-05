
import subprocess

from ghidracpp.test import run_tests

from . import rewrite_function
from .rewrite_function import FunctionRewriter, Tokenizer, decompile, initialize_ghidra_from_gzf, initialize_ghidra_from_real_project
from .rewrite_function import rewrite_function as rw


import argparse, pathlib, sys, os

parser = argparse.ArgumentParser()

#
# Shared arguments
#
common = argparse.ArgumentParser(add_help=False)

source = common.add_mutually_exclusive_group(required=True)
source.add_argument("--project-name")
source.add_argument("--gzf")

common.add_argument("--project-dir", default="")
common.add_argument("--overwrite", action="store_true")
common.add_argument("--verbose", action="store_true")
common.add_argument("--post-processor", type=str, required=False, default="")
common.add_argument("--globals-location", type=str, required=False, default="")
common.add_argument("--root-namespace", type=str, required=False, default="")
common.add_argument("--clang-format", action='store_true', required=False, default=False)

subparsers = parser.add_subparsers(dest="command", required=True)

#
# function
#
function = subparsers.add_parser(
    "function",
    parents=[common],
    help="Decompile a single function",
)

function.add_argument(
    "--name",
    required=True,
    help="Fully-qualified function name (e.g. Foo::Bar::baz)"
)

output = function.add_mutually_exclusive_group(required=True)
output.add_argument(
    "--stdout",
    action="store_true",
    help="Write to stdout",
)
output.add_argument(
    "--output",
    help="Write to an explicit output file",
)
output.add_argument(
    "--output-dir",
    help="Write <function>.cpp into this directory",
)

function.add_argument(
    "--preserve-namespaces",
    action="store_true",
    help="When using --output-dir, create namespace directories",
)

#
# namespace
#
namespace = subparsers.add_parser(
    "namespace",
    parents=[common],
    help="Decompile every function in a namespace",
)

namespace.add_argument(
    "--name",
    required=True,
    help="Namespace to decompile (e.g. Foo::Bar)"
)

namespace.add_argument(
    "--output-dir",
    required=True,
    help="Directory to write generated files into",
)

namespace.add_argument(
    "--recursive",
    action="store_true",
    help="Include subnamespaces",
)

namespace.add_argument(
    "--preserve-namespaces",
    action="store_true",
    help="Create namespace directories under the output directory",
)

#
# function
#
tests = subparsers.add_parser(
    "test",
    parents=[common],
    help="Test ghidra-cpp",
)

def create_post_processor(ppstring: str):
  if not ppstring:
    return lambda x: x
  import re
  m = re.match(pattern='^replace[(]"([^"]+)",\\s*"([^"]+)"[)]$', string=ppstring)
  if not m:
    raise Exception(f"unsupported post processing: {ppstring}")
  return lambda x: x.replace(m.group(1), m.group(2))  

def resolve_path_for_name(name: str, dir: pathlib.Path):
  dir = dir.resolve()
  function_name = name
  if "::" in name:
    parts = name.split("::")
    function_name = parts[-1]
    return (dir / ("/".join(parts[:-1]))).resolve(), f"{function_name}.cpp"
  return dir, f"{function_name}.cpp"

def optional_clang_format(contents: str):
  ps = subprocess.Popen(["clang-format"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="UTF-8")
  fnew_formatted = ps.communicate(contents)[0]
  return fnew_formatted

def main():
  args = parser.parse_args()
  if args.command in ["function", "namespace", "test"]:      
    if args.gzf:
      initialize_ghidra_from_gzf(args.gzf)
    elif args.project_name:
      dir = pathlib.Path(args.project_dir or ".").resolve().absolute()
      initialize_ghidra_from_real_project(str(dir), args.project_name)
  if args.command == "test":
    run_tests()
    return
  
  post_processor = create_post_processor(args.post_processor)
    
  name = post_processor(args.name)
  if args.command == "function":
    content = rw(function=name, root_namespace=args.root_namespace, globals_location=args.globals_location, post_processor=post_processor)
    if args.clang_format:
        content = optional_clang_format(content)
    if args.stdout:
      print(content, file=sys.stdout)
    elif args.output:
      pathlib.Path(args.output).write_bytes(content.replace("\r\n", "\n").encode('utf-8'))
    elif args.output_dir:
      output_dir, file_name = resolve_path_for_name(name, pathlib.Path(args.output_dir))
      if not args.preserve_namespaces:
        output_dir = pathlib.Path(args.output_dir)
      else:
        output_dir.mkdir(exist_ok=True, parents=True)
      dest = (output_dir / file_name)
      if not dest.exists() or args.overwrite:
        print(f"rewriting function: {dest}")
        dest.write_bytes(content.replace("\r\n", "\n").encode('utf-8'))
      else:
        print(f"skipping, already exists: {dest}", file=sys.stderr)
  elif args.command == "namespace":
    fm = rewrite_function.currentProgram.getFunctionManager()
    known_functions = [(post_processor('::'.join(str(ff) for ff in f.getPathList(True)[:-1])), f,) for f in fm.getFunctions(True)]
    if not args.recursive:
      known_functions = [(pns, f,) for pns, f in known_functions if pns == name]
    else:
      known_functions = [(pns, f,) for pns, f in known_functions if pns.startswith(name)]
    for pns, f in known_functions:
      output_dir, file_name = resolve_path_for_name(post_processor("::".join(str(ple) for ple in f.getPathList(True))), pathlib.Path(args.output_dir))
      if not args.preserve_namespaces:
        output_dir = pathlib.Path(args.output_dir)
      else:
        output_dir.mkdir(exist_ok=True, parents=True)
      dest = (output_dir / file_name)
      if not dest.exists() or args.overwrite:
        print(f"rewriting function: {dest}")
        contents = rw(function=f, root_namespace = args.root_namespace, globals_location=args.globals_location, post_processor=post_processor).replace("\r\n", "\n")
        if args.clang_format:
          contents = optional_clang_format(contents)
        dest.write_bytes(data=contents.encode('utf-8'))
      else:
        print(f"skipping, already exists: {dest}")
  

    
    