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
