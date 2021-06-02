import sys
import inspect
import z3
import ast
import astor
from fuzzingbook.ControlFlow import PyCFG, CFGNode, to_graph, gen_cfg
from graphviz import Source, Graph
from fuzzingbook.Fuzzer import Fuzzer
from contextlib import contextmanager


MAX_ITER = 100
MAX_TRIES = 100
MAX_DEPTH = 100

def show_cfg(fn, **kwargs):
    return Source(to_graph(gen_cfg(inspect.getsource(fn)), **kwargs))

def get_annotations(fn):
    sig = inspect.signature(fn)
    return ([(i.name, i.annotation)
             for i in sig.parameters.values()], sig.return_annotation)

SYM_VARS = {
    int: (
        z3.Int, z3.IntVal), float: (
            z3.Real, z3.RealVal), str: (
                z3.String, z3.StringVal)}
def get_symbolicparams(fn):
    params, ret = get_annotations(fn)
    return [SYM_VARS[typ][0](name)
            for name, typ in params], SYM_VARS[ret][0]('__return__')

def to_src(astnode):
    return astor.to_source(astnode).strip()


def get_expression(src):
    return ast.parse(src).body[0].value

def prefix_vars(astnode, prefix):
    if isinstance(astnode, ast.BoolOp):
        return ast.BoolOp(astnode.op,
                          [prefix_vars(i, prefix) for i in astnode.values], [])
    elif isinstance(astnode, ast.BinOp):
        return ast.BinOp(
            prefix_vars(astnode.left, prefix), astnode.op,
            prefix_vars(astnode.right, prefix))
    elif isinstance(astnode, ast.UnaryOp):
        return ast.UnaryOp(astnode.op, prefix_vars(astnode.operand, prefix))
    elif isinstance(astnode, ast.Call):
        return ast.Call(prefix_vars(astnode.func, prefix),
                        [prefix_vars(i, prefix) for i in astnode.args],
                        astnode.keywords)
    elif isinstance(astnode, ast.Compare):
        return ast.Compare(
            prefix_vars(astnode.left, prefix), astnode.ops,
            [prefix_vars(i, prefix) for i in astnode.comparators])
    elif isinstance(astnode, ast.Name):
        if astnode.id in {'And', 'Or', 'Not'}:
            return ast.Name('z3.%s' % (astnode.id), astnode.ctx)
        else:
            return ast.Name('%s%s' % (prefix, astnode.id), astnode.ctx)
    elif isinstance(astnode, ast.Return):
        return ast.Return(prefix_vars(astnode.value, env))
    else:
        return astnode



def z3_names_and_types(z3_ast):
    hm = {}
    children = z3_ast.children()
    if children:
        for c in children:
            hm.update(z3_names_and_types(c))
    else:
        if (str(z3_ast.decl()) != str(z3_ast.sort())):
            hm["%s" % str(z3_ast.decl())] = 'z3.%s' % str(z3_ast.sort())
        else:
            pass
    return hm

def used_identifiers(src):
    def names(astnode):
        lst = []
        if isinstance(astnode, ast.BoolOp):
            for i in astnode.values:
                lst.extend(names(i))
        elif isinstance(astnode, ast.BinOp):
            lst.extend(names(astnode.left))
            lst.extend(names(astnode.right))
        elif isinstance(astnode, ast.UnaryOp):
            lst.extend(names(astnode.operand))
        elif isinstance(astnode, ast.Call):
            for i in astnode.args:
                lst.extend(names(i))
        elif isinstance(astnode, ast.Compare):
            lst.extend(names(astnode.left))
            for i in astnode.comparators:
                lst.extend(names(i))
        elif isinstance(astnode, ast.Name):
            lst.append(astnode.id)
        elif isinstance(astnode, ast.Expr):
            lst.extend(names(astnode.value))
        elif isinstance(astnode, (ast.Num, ast.Str, ast.Tuple, ast.NameConstant)):
            pass
        elif isinstance(astnode, ast.Assign):
            for t in astnode.targets:
                lst.extend(names(t))
            lst.extend(names(astnode.value))
        elif isinstance(astnode, ast.Module):
            for b in astnode.body:
                lst.extend(names(b))
        else:
            raise Exception(str(astnode))
        return list(set(lst))
    return names(ast.parse(src))


Function_Summaries = {}
Function_Summaries['function_name'] = {
    'predicate': "",
    'vars': {}}

SYM_VARS_STR = {
    k.__name__: ("z3.%s" % v1.__name__, "z3.%s" % v2.__name__)
    for k, (v1, v2) in SYM_VARS.items()
}


def translate_to_z3_name(v):
    return SYM_VARS_STR[v][0]


def declarations(astnode, hm=None):
    if hm is None:
        hm = {}
    if isinstance(astnode, ast.Module):
        for b in astnode.body:
            declarations(b, hm)
    elif isinstance(astnode, ast.FunctionDef):

        for a in astnode.args.args:
            hm[a.arg] = translate_to_z3_name(a.annotation.id)
        for b in astnode.body:
            declarations(b, hm)
        # hm[astnode.name + '__return__'] = translate_to_z3_name(astnode.returns.id)
    elif isinstance(astnode, ast.Call):
        n = astnode.function
        assert isinstance(n, ast.Name)
        name = n.id
        hm.update(dict(Function_Summaries[name]['vars']))
    elif isinstance(astnode, ast.AnnAssign):
        assert isinstance(astnode.target, ast.Name)
        hm[astnode.target.id] = translate_to_z3_name(astnode.annotation.id)
    elif isinstance(astnode, ast.Assign):
        for t in astnode.targets:
            assert isinstance(t, ast.Name)
            assert t.id in hm
    elif isinstance(astnode, ast.AugAssign):
        assert isinstance(astnode.target, ast.Name)
        assert astnode.target.id in hm
    elif isinstance(astnode, (ast.If, ast.For, ast.While)):
        for b in astnode.body:
            declarations(b, hm)
        for b in astnode.orelse:
            declarations(b, hm)
    elif isinstance(astnode, ast.Return):
        pass
    else:
        raise Exception(str(astnode))
    return hm


def define_symbolic_vars(fn_vars, prefix):
    sym_var_dec = ', '.join([prefix + n for n in fn_vars])
    sym_var_def = ', '.join(["%s('%s%s')" % (t, prefix, n)
                             for n, t in fn_vars.items()])
    return "%s = %s" % (sym_var_dec, sym_var_def)

def used_vars(fn):
    return declarations(ast.parse(inspect.getsource(fn)))

def gen_fn_summary(prefix, fn):
    summary = Function_Summaries[fn.__name__]['predicate']
    fn_vars = Function_Summaries[fn.__name__]['vars']
    decl = define_symbolic_vars(fn_vars, prefix)
    summary_ast = get_expression(summary)
    return decl, to_src(prefix_vars(summary_ast, prefix))

@contextmanager
def checkpoint(z3solver):
    z3solver.push()
    yield z3solver
    z3solver.pop()


