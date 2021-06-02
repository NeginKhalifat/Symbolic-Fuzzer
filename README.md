# SymbolicFuzzer
This project aims to develop a symbolic fuzzer to `generate all possible paths` to a given depth, collect the information about the `constraint and possible input` for the given example with variables which annotated with the type information.

## prerequisites: 
in windows:
```
$ git clone https://github.com/SotwareTesting-Project/Symbolic-Fuzzer.git
$ python3 -m venv environment_name
$ .\environment_name\Scripts\activate.bat
$ cd Symbolic-Fuzzer
$ pip install -r requirements.txt
```
## to Run: 
in windows:
```
$ python src\main.py -i Examples\simpleIfElse.py –d 10
```
