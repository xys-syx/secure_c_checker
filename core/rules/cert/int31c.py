import re
from pycparser import c_ast
from core.rule import Rule

class INT31C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "INT31-C"
        self.name = "Ensure integer conversions do not lose or misinterpret data"
        self._violations = []
        self._int_types = {}

    def visit_Decl(self, node):
        if isinstance(node.type, c_ast.TypeDecl) and isinstance(node.type.type, c_ast.IdentifierType):
            type_names = node.type.type.names
            widths = {"char": 8, "short": 16, "int": 32, "long": 32, "long long": 64}
            signed = True
            width = None
            for t in type_names:
                if t in ["unsigned", "_Bool"]:
                    signed = False
                if t in widths:
                    width = widths[t]
            if width:
                self._int_types[node.name] = {"width": width, "signed": signed}
        self.generic_visit(node)

    def visit_Cast(self, node):
        if isinstance(node.to_type.type, c_ast.IdentifierType):
            target_names = node.to_type.type.names
            target_signed = True
            target_width = None
            widths = {"char": 8, "short": 16, "int": 32, "long": 32, "long long": 64}
            for t in target_names:
                if t == "unsigned":
                    target_signed = False
                if t in widths:
                    target_width = widths[t]
            src_signed = None
            src_width = None
            if isinstance(node.expr, c_ast.ID) and node.expr.name in self._int_types:
                src_info = self._int_types[node.expr.name]
                src_signed, src_width = src_info["signed"], src_info["width"]
            if src_width and target_width:
                if target_width < src_width or target_signed != src_signed:
                    self._report(node)
        self.generic_visit(node)

    def _report(self, node):
        self._violations.append({
            "rule": self.id,
            "message": f"Potential dangerous conversion at line {node.coord.line}"
        })

    def analyze(self, code, filename="<unknown>", tainted_vars=None):
        return
