import z3

from HelperFunc import to_src, used_identifiers, define_symbolic_vars, checkpoint
from PNode import PNode
from SymbolicFuzzer import SimpleSymbolicFuzzer, to_single_assignment_predicates, identifiers_with_types


class AdvancedSymbolicFuzzer(SimpleSymbolicFuzzer):
    def options(self, kwargs):
        super().options(kwargs)

    def extract_constraints(self, path):
        tpath, ok = to_single_assignment_predicates(path)
        res = []
        if ok:
            for p in tpath:
                if p != None:
                    res.append(to_src(p))
        else:
            res = []
        return res
    def solve_path_constraint(self, path):
        # re-initializing does not seem problematic.
        # a = z3.Int('a').get_id() remains the same.
        constraints = self.extract_constraints(path)
        identifiers = [
            c for i in constraints for c in used_identifiers(i)]  # <- changes
        with_types = identifiers_with_types(
            identifiers, self.used_variables)  # <- changes
        decl = define_symbolic_vars(with_types, '')
        exec (decl)

        solutions = {}
        with checkpoint(self.z3):
            st = 'self.z3.add(%s)' % ', '.join(constraints)
            eval(st)
            if self.z3.check() != z3.sat:
                return {}
            m = self.z3.model()
            solutions = {d.name(): m[d] for d in m.decls()}
            my_args = {k: solutions.get(k, None) for k in self.fn_args}
        predicate = 'z3.And(%s)' % ','.join(
            ["%s == %s" % (k, v) for k, v in my_args.items()])
        eval('self.z3.add(z3.Not(%s))' % predicate)
        return my_args

    def get_next_path(self):
        self.last_path -= 1
        if self.last_path == -1:
            self.last_path = len(self.paths) - 1
        return self.paths[self.last_path]

    def get_all_paths(self, fenter):
        path_lst = [PNode(0, fenter)]
        completed = []
        for i in range(self.max_iter):
            new_paths = [PNode(0, fenter)]
            for path in path_lst:
                # explore each path once
                if path.cfgnode.children:
                    np = path.explore()
                    for p in np:
                        if path.idx > self.max_depth:
                            break
                        new_paths.append(p)
                else:
                    completed.append(path)
            path_lst = new_paths
        return completed + path_lst

    def can_be_satisfied(self, p):
        s2 = self.extract_constraints(p.get_path_to_root())
        s = z3.Solver()
        identifiers = [c for i in s2 for c in used_identifiers(i)]
        with_types = identifiers_with_types(identifiers, self.used_variables)
        decl = define_symbolic_vars(with_types, '')
        exec(decl)
        exec("s.add(z3.And(%s))" % ','.join(s2), globals(), locals())
        return s.check() == z3.sat

    def solve_constraint(self, constraints, pNodeList):
        identifiers = [c for i in constraints for c in used_identifiers(i)]
        with_types = identifiers_with_types(identifiers, self.used_variables)
        decl = define_symbolic_vars(with_types, '')
        exec(decl)
        with checkpoint(self.z3):
            unsat_result = {}
            unsat_result['constraint'] = []
            unsat_result['unsat_core'] = []
            unsat_result['statement'] = []
            unsat_result['path'] = [constraints]
            unsat_path = {}

            i = 0
            for cons in constraints:
                unsat_result['constraint'].append(str(cons))
                assert_constraint = 'self.z3.assert_and_track(%s,"p%s")' % (cons, str(i))
                i = i + 1
                path_name = 'p' + str(i)
                unsat_path[z3.Bool(path_name)] = cons
                eval(assert_constraint)
            if self.z3.check() != z3.sat:
                unsat_core = self.z3.unsat_core()
                unsat_result['unsat_core'].append("Unsat core: ")
                for i in range(len(unsat_core)):
                    if unsat_core[i] not in unsat_path:
                        continue
                    unsat_result['unsat_core'].append("\t" + str(unsat_path[unsat_core[i]]))
                unsat_result['statement'].append("Unsat path statements: ")
                for node in pNodeList:
                    cfg = node.cfgnode.to_json()
                    at = cfg['at']
                    ast = cfg['ast']
                    unsat_result['statement'].append("\t#line " + str(at) + ": " + str(ast))
                return unsat_result, True
            test_case = self.z3.model()
            solutions = {x.name(): test_case[x] for x in test_case.decls()}
            arguments = {y: solutions.get(y, None) for y in self.fn_args}
        predicate = 'z3.And(%s)' % ','.join(["%s == %s" % (x, y) for x, y in arguments.items() if y is not None])
        eval('self.z3.add(z3.Not(%s))' % predicate)
        return arguments, False

