from pycparser import c_ast
from core.rule import Rule


class MEM30C(Rule, c_ast.NodeVisitor):
    _alloc_funcs = {"malloc", "calloc", "realloc"}
    _free_funcs  = {"free"}
    _realloc     = "realloc"

    def __init__(self):
        super().__init__()
        self.id   = "MEM30-C"
        self.name = "Do not access freed memory"
        # per-function tracking
        self._freed = set()

    def check(self, ast, filename="<unknown>", tainted_vars=None):
        self._violations = []
        self.filename = filename
        for ext in ast.ext:
            if isinstance(ext, c_ast.FuncDef):
                self._freed.clear()
                self.visit(ext.body)
        return self._violations

    def _report(self, coord, label, msg):
        self._violations.append({
            "file": self.filename,
            "line": coord.line if coord else 0,
            "rule": self.id,
            "severity": "HIGH",
            "description": f"[{label}] {msg}"
        })

    def _mark_freed(self, var_name, coord):
        if var_name in self._freed:
            self._report(coord, "DOUBLE-FREE",
                         f"pointer '{var_name}' freed more than once")
        self._freed.add(var_name)

    def visit_FuncCall(self, node):
        fname = node.name.name if isinstance(node.name, c_ast.ID) else None

        if node.args:
            for arg in node.args.exprs:
                self.visit(arg)

        if fname in self._free_funcs and node.args and len(node.args.exprs) == 1:
            arg = node.args.exprs[0]
            if isinstance(arg, c_ast.ID):
                self._mark_freed(arg.name, node.coord)
            return

        if fname == self._realloc and node.args and len(node.args.exprs) >= 2:
            ptr   = node.args.exprs[0]
            sizee = node.args.exprs[1]
            if (isinstance(sizee, c_ast.Constant) and
                    sizee.type == "int" and sizee.value == "0"):
                if isinstance(ptr, c_ast.ID):
                    self._mark_freed(ptr.name, node.coord)

    def visit_Assignment(self, node):
        self.visit(node.rvalue)

        if isinstance(node.lvalue, c_ast.ID):
            lhs = node.lvalue.name
            if isinstance(node.rvalue, c_ast.ID) and node.rvalue.name in self._freed:
                self._freed.add(lhs)
                return
            if self._is_allocator_call(node.rvalue) or self._is_null(node.rvalue):
                self._freed.discard(lhs)
                return
        self.visit(node.lvalue)

    def visit_ID(self, node):
        if node.name in self._freed:
            self._report(node.coord, "USE-AFTER-FREE",
                         f"using freed pointer '{node.name}'")

    def visit_UnaryOp(self, node):
        if node.op == '*' and isinstance(node.expr, c_ast.ID):
            if node.expr.name in self._freed:
                self._report(node.coord, "USE-AFTER-FREE",
                             f"dereferencing freed pointer '{node.expr.name}'")
        self.generic_visit(node)

    def visit_BinaryOp(self, node):
        self.visit(node.left)
        self.visit(node.right)

    def visit_Cast(self, node):
        self.visit(node.expr)

    def visit_ArrayRef(self, node):
        if isinstance(node.name, c_ast.ID) and node.name.name in self._freed:
            self._report(node.coord, "USE-AFTER-FREE",
                         f"indexing freed pointer '{node.name.name}'")
        self.generic_visit(node)

    def visit_StructRef(self, node):
        if node.type == '->' and isinstance(node.name, c_ast.ID):
            if node.name.name in self._freed:
                self._report(node.coord, "USE-AFTER-FREE",
                             f"accessing field of freed pointer '{node.name.name}'")
        self.generic_visit(node)

    def _is_null(self, expr):
        return (isinstance(expr, c_ast.Constant) and expr.type == "int" and expr.value == "0") or \
               (isinstance(expr, c_ast.ID) and expr.name == "NULL")

    def _is_allocator_call(self, expr):
        if isinstance(expr, c_ast.FuncCall):
            if isinstance(expr.name, c_ast.ID) and expr.name.name in self._alloc_funcs:
                # size arg == 0 for realloc counted as free, we treat >0 as alloc
                if expr.name.name == "realloc" and expr.args and len(expr.args.exprs) >= 2:
                    size_arg = expr.args.exprs[1]
                    if isinstance(size_arg, c_ast.Constant) and size_arg.value == "0":
                        return False
                return True
        return False
