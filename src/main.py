import argparse
import ast
import astor
from fuzzingbook.ControlFlow import PyCFG
from advancedfuzzer import AdvancedSymbolicFuzzer

MAX_ITER = 100
MAX_TRIES = 100
MAX_DEPTH = 100

def main(args):
    global MAX_DEPTH
    MAX_DEPTH = args.depth

    results = []
    astree = astor.parse_file(args.input)
    src_code = astor.to_source(astree)
    py_cfg = PyCFG()
    function_names, function_CFGs = create_CFG(py_cfg, astree)

    for i in range(len(function_names)):
        print("###################################" + function_names[i] + "###################################")
        results += analyze(function_names[i], src_code, py_cfg)

def create_CFG(py_cfg, astree):
    function_names = []
    function_CFGs = {}
    for node in ast.walk(astree):
        if isinstance(node, ast.FunctionDef):  # if node is a function in python
            function_names.append(node.name)
            function_CFGs[node.name] = py_cfg.gen_cfg(astor.to_source(node))
    return function_names, function_CFGs

def analyze(func_name, src_code, py_CFG):
    results = []
    single_result = {}

    advanced_fuzzer = AdvancedSymbolicFuzzer(func_name, src_code, py_CFG)
    paths = advanced_fuzzer.get_all_paths(advanced_fuzzer.fnenter)

    count_path = 0
    used_constraint = []

    for i in range(len(paths)):
        constraint = advanced_fuzzer.extract_constraints(paths[i].get_path_to_root())
        concat_constraint = '__'.join(constraint)
        if concat_constraint in used_constraint or len(constraint) <= 1:
            continue
        used_constraint.append(concat_constraint)
        # print(used_constraint)
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Argument parser')

    parser.add_argument("-i", "--input", help="input path", type=str, required=True)
    parser.add_argument("-d", "--depth", help="max depth", type=int, required=True)
    args = parser.parse_args()
    main(args)