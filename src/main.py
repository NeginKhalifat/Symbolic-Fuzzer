import argparse


def main(args):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Argument parser')

    parser.add_argument("-i", "--input", help="input path", type=str, required=True)
    parser.add_argument("-d", "--depth", help="max depth", type=int, required=True)
    args = parser.parse_args()
    main(args)