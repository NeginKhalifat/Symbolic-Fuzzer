import sys
import inspect
import z3
import ast
import astor
from fuzzingbook.ControlFlow import PyCFG, CFGNode, to_graph, gen_cfg
from graphviz import Source, Graph
from fuzzingbook.Fuzzer import Fuzzer
from contextlib import contextmanager

from HelperFunc import declarations, to_src, define_symbolic_vars, checkpoint, MAX_DEPTH, MAX_TRIES, MAX_ITER


class SimpleSymbolicFuzzer(Fuzzer):
    def __init__(self, func_name , src_code, py_cfg, **kwargs):
        self.fn_name = func_name

        self.py_cfg = py_cfg
        self.fnenter, self.fnexit = self.py_cfg.functions[self.fn_name]

        # dictionary of used variables
        self.used_variables = declarations(ast.parse(src_code))

        # list of arguments
        self.fn_args = list(self.used_variables.keys())

        self.z3 = z3.Solver()

        self.paths = None
        self.last_path = None

        self.options(kwargs)
        self.process()

    def process(self):
        self.paths = self.get_all_paths(self.fnenter)
        self.last_path = len(self.paths)

    def options(self, kwargs):
        self.max_depth = kwargs.get('max_depth', MAX_DEPTH)
        self.max_tries = kwargs.get('max_tries', MAX_TRIES)
        self.max_iter = kwargs.get('max_iter', MAX_ITER)
        self._options = kwargs
    
    def get_all_paths(self, fenter, depth=0):
        if depth > self.max_depth:
            raise Exception('Maximum depth exceeded')
        if not fenter.children:
            return [[(0, fenter)]]

        fnpaths = []
        for idx, child in enumerate(fenter.children):
            child_paths = self.get_all_paths(child, depth + 1)
            for path in child_paths:
                # In a conditional branch, idx is 0 for IF, and 1 for Else
                fnpaths.append([(idx, fenter)] + path)
        return fnpaths
    
    def extract_constraints(self, path):
        predicates = []
        for (idx, elt) in path:
            if isinstance(elt.ast_node, ast.AnnAssign):
                if elt.ast_node.target.id in {'_if', '_while'}:
                    s = to_src(elt.ast_node.annotation)
                    if ( s[0] != '('):
                        s = '('+ s+ ')'
                    predicates.append(("%s" if idx == 0 else "z3.Not%s") % s)
                elif isinstance(elt.ast_node.annotation, ast.Call):
                    assert elt.ast_node.annotation.func.id == self.fn_name
                else:
                    node = elt.ast_node
                    t = ast.Compare(node.target, [ast.Eq()], [node.value])
                    predicates.append(to_src(t))
            elif isinstance(elt.ast_node, ast.Assign):
                node = elt.ast_node
                t = ast.Compare(node.targets[0], [ast.Eq()], [node.value])
                predicates.append(to_src(t))
            else:
                pass
        return predicates

    def solve_path_constraint(self, path):
        # re-initializing is problematic.
        constraints = self.extract_constraints(path)
        decl = define_symbolic_vars(self.used_variables, '')
        exec(decl)

        solutions = {}
        with checkpoint(self.z3):
            st = 'self.z3.add(%s)' % ', '.join(constraints)
            eval(st)                     
            if self.z3.check() != z3.sat:
                return {}
            m = self.z3.model()
            solutions = {d.name(): m[d] for d in m.decls()}
            my_args = {k: solutions.get(k, False) for k in self.fn_args}
        predicate = 'z3.And(%s)' % ','.join(
            ["%s == %s" % (k, v) for k, v in my_args.items()])
        eval('self.z3.add(z3.Not(%s))' % predicate)
        return my_args
    
    def get_next_path(self):
        self.last_path -= 1
        if self.last_path == -1:
            self.last_path = len(self.paths) - 1
        return self.paths[self.last_path]
    
    def fuzz(self):
        for i in range(self.max_tries):
            res = self.solve_path_constraint(self.get_next_path())
            if res:
                return res
        return {}


#for using in reassignments and loops
def rename_variables(astnode, env):
    if isinstance(astnode, ast.BoolOp):
        fn = 'z3.And' if isinstance(astnode.op, ast.And) else 'z3.Or'
        return ast.Call(
            ast.Name(fn, None),
            [rename_variables(i, env) for i in astnode.values], [])
    elif isinstance(astnode, ast.BinOp):
        return ast.BinOp(
            rename_variables(astnode.left, env), astnode.op,
            rename_variables(astnode.right, env))
    elif isinstance(astnode, ast.UnaryOp):
        if isinstance(astnode.op, ast.Not):
            return ast.Call(
                ast.Name('z3.Not', None),
                [rename_variables(astnode.operand, env)], [])
        else:
            return ast.UnaryOp(astnode.op,
                               rename_variables(astnode.operand, env))
    elif isinstance(astnode, ast.Call):
        return ast.Call(astnode.func,
                        [rename_variables(i, env) for i in astnode.args],
                        astnode.keywords)
    elif isinstance(astnode, ast.Compare):
        return ast.Compare(
            rename_variables(astnode.left, env), astnode.ops,
            [rename_variables(i, env) for i in astnode.comparators])
    elif isinstance(astnode, ast.Name):
        if astnode.id not in env:
            env[astnode.id] = 0
        num = env[astnode.id]
        return ast.Name('_%s_%d' % (astnode.id, num), astnode.ctx)
    elif isinstance(astnode, ast.Subscript):
        identifier = to_src(astnode)
        name = identifier[:-3] + '_' + identifier[-2]
        if name not in env:
            env[name] = 0
        num = env[name]
        return ast.Name('_%s_%d' % (name, num), astnode.ctx)
    elif isinstance(astnode, ast.Return):
        return ast.Return(rename_variables(astnode.value, env))
    else:
        return astnode


def to_single_assignment_predicates(path):
    env = {}
    new_path = []
    completed_path = False
    for i, node in enumerate(path):
        ast_node = node.cfgnode.ast_node
        new_node = None
        if isinstance(ast_node, ast.AnnAssign) and ast_node.target.id in {
                'exit'}:
            completed_path = True
            new_node = None
        elif isinstance(ast_node, ast.AnnAssign) and ast_node.target.id in {'enter'}:
            args = [
                ast.parse(
                    "%s == _%s_0" %
                    (a.id, a.id)).body[0].value for a in ast_node.annotation.args]
            new_node = ast.Call(ast.Name('z3.And', None), args, [])
        elif isinstance(ast_node, ast.AnnAssign) and ast_node.target.id in {'_if', '_while'}:
            new_node = rename_variables(ast_node.annotation, env)
            if node.order != 0:
                # assert node.order == 1
                if node.order != 1:
                    return [], False
                new_node = ast.Call(ast.Name('z3.Not', None), [new_node], [])
        elif isinstance(ast_node, ast.AnnAssign):
            if isinstance(ast_node.value, ast.List):
                for idx, element in enumerate(ast_node.value.elts):
                    assigned = ast_node.target.id + "_" + str(idx)
                    val = [rename_variables(element, env)]
                    env[assigned] = 0
                    target = ast.Name('_%s_%d' % (assigned, env[assigned]), None)
                    new_path.append(ast.Expr(ast.Compare(target, [ast.Eq()], val)))
                pass
            else:
                assigned = ast_node.target.id
                val = [rename_variables(ast_node.value, env)]
                env[assigned] = 0 if assigned not in env else env[assigned] + 1
                target = ast.Name('_%s_%d' % (assigned, env[assigned]), None)
                new_node = ast.Expr(ast.Compare(target, [ast.Eq()], val))
        elif isinstance(ast_node, ast.Assign):
            if isinstance(ast_node.targets[0], ast.Subscript):
                identifier = to_src(ast_node.targets[0])
                assigned = identifier[:-3] + '_' + identifier[-2]
                val = [rename_variables(ast_node.value, env)]
                env[assigned] = 0 if assigned not in env else env[assigned] + 1
                target = ast.Name('_%s_%d' % (assigned, env[assigned]), None)
            else:
                assigned = ast_node.targets[0].id
                val = [rename_variables(ast_node.value, env)]
                env[assigned] = 0 if assigned not in env else env[assigned] + 1
                target = ast.Name('_%s_%d' % (assigned, env[assigned]), None)
            new_node = ast.Expr(ast.Compare(target, [ast.Eq()], val))
        elif isinstance(ast_node, (ast.Return, ast.Pass)):
            new_node = None
        else:
            continue
            # s = "NI %s %s" % (type(ast_node), ast_node.target.id)
            # raise Exception(s)
        new_path.append(new_node)
    return new_path, completed_path


def identifiers_with_types(identifiers, defined):
    with_types = dict(defined)
    for i in identifiers:
        if i[0] == '_':
            if i.count('_') > 2:
                last = i.rfind('_')
                name = i[1:last]
            else:
                nxt = i[1:].find('_', 1)
                name = i[1:nxt + 1]
            assert name in defined
            typ = defined[name]
            with_types[i] = typ
    return with_types
  
#---------------------------------------------------------------------------------
# test class SimpleSympolicFuzzer
# def fun(a: int,b: int,c: int):
#     x: int = 0
#     y: int = 0
#     z: int = 0
#     if (a >= 0):
#         return -2
    
#     if (b < 5):
#         if (a <= 0):
#             if( c < 7):
#                 return 1
#         return 2
#     return x + y + z

# symfz_ct = SimpleSymbolicFuzzer(fun)
# for i in range(1, 10):
#     r = symfz_ct.fuzz()
#     print(r)
#----------------------------------------------------------------------------------