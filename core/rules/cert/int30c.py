from pycparser import c_ast
from core.rule import Rule

class INT30C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "INT30-C"
        self.name = "Ensure unsigned integer operations do not wrap"
        self._violations = []
        self._unsigned_vars = set()

    def visit_Decl(self, node):
        if isinstance(node.type, c_ast.TypeDecl):
            type_specs = node.type.type.names if isinstance(node.type.type, c_ast.IdentifierType) else []
            if "unsigned" in type_specs:
                self._unsigned_vars.add(node.name)
        self.generic_visit(node)

    def visit_BinaryOp(self, node):
        if node.op in {"+", "-", "*"}:
            def is_unsigned_var(expr):
                return isinstance(expr, c_ast.ID) and expr.name in self._unsigned_vars
            if is_unsigned_var(node.left) or is_unsigned_var(node.right):
                self._report(node)
        self.generic_visit(node)

    def _report(self, node):
        self._violations.append({
            "rule": self.id,
            "message": f"Possible unsigned overflow in expression at line {node.coord.line}"
        })

    def analyze(self, code, filename="<unknown>", tainted_vars=None):
        return
