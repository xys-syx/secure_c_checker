from pycparser import c_ast
from core.rule import Rule


class ARR30C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = "ARR30-C"
        self.name = "No out-of-bounds pointers or subscripts"
        self._arrays = {}
        self.filename = "<stdin>"
        self._violations = []

    def check(self, ast, filename="<unknown>", tainted_vars=None):
        self._arrays.clear()
        self._violations.clear()
        self.filename = filename
        self.visit(ast)
        return self._violations

    def _report(self, coord, msg):
        self._violations.append({
            "file": self.filename,
            "line": coord.line if coord else 0,
            "rule": self.id,
            "severity": "HIGH",
            "description": "[OOB] " + msg
        })

    @staticmethod
    def _const_int(expr):
        if isinstance(expr, c_ast.Constant) and expr.type == "int":
            try:
                return int(expr.value, 0)
            except ValueError:
                return None
        if isinstance(expr, c_ast.UnaryOp) and expr.op in ('-', '+'):
            inner = ARR30C._const_int(expr.expr)
            if inner is not None:
                return -inner if expr.op == '-' else +inner

    def visit_Decl(self, node):
        if isinstance(node.type, c_ast.ArrayDecl):
            size = self._const_int(node.type.dim)
            if size is not None:
                self._arrays[node.name] = size
        self.generic_visit(node)

    def visit_ArrayRef(self, node):
        if isinstance(node.name, c_ast.ID) and node.name.name in self._arrays:
            size = self._arrays[node.name.name]
            idx_val = self._const_int(node.subscript)
            if idx_val is not None:
                if idx_val < 0 or idx_val >= size:
                    self._report(node.coord,
                                 f"{node.name.name}[{idx_val}] is outside 0..{size-1}")
        self.generic_visit(node)

    def visit_BinaryOp(self, node):
        if node.op == '+':
            lhs_size = None
            rhs_const = None

            if isinstance(node.left, c_ast.ID) and node.left.name in self._arrays:
                lhs_size = self._arrays[node.left.name]
                rhs_const = self._const_int(node.right)
                base = node.left.name

            elif isinstance(node.right, c_ast.ID) and node.right.name in self._arrays:
                lhs_size = self._arrays[node.right.name]
                rhs_const = self._const_int(node.left)
                base = node.right.name
            if lhs_size is not None and rhs_const is not None:
                if rhs_const < 0 or rhs_const > lhs_size:
                    self._report(node.coord,
                                 f"pointer {base}+{rhs_const} forms OOB address "
                                 f"(array size {lhs_size})")
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if node.op == '*' and isinstance(node.expr, c_ast.BinaryOp):
            self.visit(node.expr)
        self.generic_visit(node)

    def visit_StructRef(self, node):
        self.generic_visit(node)
