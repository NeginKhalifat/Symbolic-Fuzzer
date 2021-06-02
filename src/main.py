import argparse
import ast
import astor
from fuzzingbook.ControlFlow import PyCFG
from advancedfuzzer import AdvancedSymbolicFuzzer

import HelperFunc


def main(args):
    HelperFunc.MAX_DEPTH = args.depth

    results = []
    astree = astor.parse_file(args.input)
    src_code = astor.to_source(astree)
    py_cfg = PyCFG()
    function_names, function_CFGs = create_CFG(py_cfg, astree)

    for i in range(len(function_names)):
        print("###################################" + function_names[i] + "###################################")
        results += analyze(function_names[i], src_code, py_cfg, function_names)

def create_CFG(py_cfg, astree):
    function_names = []
    function_CFGs = {}
    for node in ast.walk(astree):
        if isinstance(node, ast.FunctionDef):  # if node is a function in python
            function_names.append(node.name)
            function_CFGs[node.name] = py_cfg.gen_cfg(astor.to_source(node))
    return function_names, function_CFGs

def assign_value_to_argument(call_function_with_constant, constraint):
    constraint_args = constraint[0]
    if 'z3.And(' in constraint_args:
        args = constraint_args.split('(')[1].split(')')[0].split(',')
        if len(args) != len(call_function_with_constant):
            return constraint
        for i, (x, y) in enumerate(zip(args, call_function_with_constant)):
            if y != 'None':
                new_var = x.split('==')[-1].strip()
                if is_constant_assigned(constraint):
                    continue
                temp = new_var + ' == ' + str(y)
                constraint.insert(1, temp)
    return constraint

def analyze(func_name, src_code, py_CFG, function_names, call_function_with_constant=[]):
    advanced_fuzzer = AdvancedSymbolicFuzzer(func_name, src_code, py_CFG)
    paths = advanced_fuzzer.get_all_paths(advanced_fuzzer.fnenter)
    report = {}
    report[func_name] = []
    functions_with_constant = {}
    results = []
    used_constraint = []
    path_count = 0
    for i in range(len(paths)):
        constraint = advanced_fuzzer.extract_constraints(paths[i].get_path_to_root())
        concat_constraint = '__'.join(constraint)
        if concat_constraint in used_constraint or len(constraint) <= 1:
            continue
        path_count += 1
        used_constraint.append(concat_constraint)
        constraint, constant_for_sub_function = seperate_function_call_constraints(constraint, function_names)
        if call_function_with_constant:
            constraint = assign_value_to_argument(call_function_with_constant, constraint)

        functions_with_constant.update(constant_for_sub_function)
        test_case, is_unsat = advanced_fuzzer.solve_constraint(constraint, paths[i].get_path_to_root())
        test_case['constraint'] = constraint
        if call_function_with_constant:
            test_case['constant'] = call_function_with_constant
        report[func_name].append(test_case)
    results.append(report)

    results += call_sub_function(functions_with_constant, src_code, function_names, py_CFG)
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Argument parser')

    parser.add_argument("-i", "--input", help="input path", type=str, required=True)
    parser.add_argument("-d", "--depth", help="max depth", type=int, required=True)
    args = parser.parse_args()
    main(args)