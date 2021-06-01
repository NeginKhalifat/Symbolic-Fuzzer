import argparse

import astor
from fuzzingbook.ControlFlow import PyCFG


def main(args):
    global MAX_DEPTH
    MAX_DEPTH = args.depth

    results = []
    astree = astor.parse_file(args.input)
    py_cfg = PyCFG()
    function_names, function_CFGs = create_CFG(py_cfg, astree)

    for i in range(len(function_names)):
        print("###################################" + function_names[i] + "###################################")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Argument parser')

    parser.add_argument("-i", "--input", help="input path", type=str, required=True)
    parser.add_argument("-d", "--depth", help="max depth", type=int, required=True)
    args = parser.parse_args()
    main(args)
