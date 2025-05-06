import re
from rule import Rule
from pycparser import c_ast
class MEM35C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "MEM35-C"
        self.name = "Allocate sufficient memory for an object"
        self._violations = []
        self._ptr_vars = set()

    def visit_Decl(self, node):
        if isinstance(node.type, c_ast.PtrDecl):
            if hasattr(node, 'name'):
                self._ptr_vars.add(node.name)
        self.generic_visit(node)

    def visit_FuncCall(self, node):
        if isinstance(node.name, c_ast.ID) and node.name.name in {"malloc", "calloc"}:
            for arg in node.args.exprs if node.args else []:
                if isinstance(arg, c_ast.UnaryOp) and arg.op == 'sizeof':
                    inner = arg.expr
                    issue = False
                    if isinstance(inner, c_ast.ID):
                        if inner.name in self._ptr_vars:
                            issue = True
                    if isinstance(inner, c_ast.Typename) and isinstance(inner.type, c_ast.PtrDecl):
                        issue = True
                    if issue:
                        self._violations.append({
                            "rule": self.id,
                            "message": f"Suspicious sizeof usage in {node.name.name} at line {node.coord.line} (check allocation size)"
                        })
        self.generic_visit(node)
