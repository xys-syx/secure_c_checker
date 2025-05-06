import re
from pycparser import c_ast
from core.rule import Rule

class CON33C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "CON33-C"
        self.name = "Avoid race conditions when using library functions"
        self._violations = []
        self._unsafe_funcs = {"strtok", "asctime", "ctime", "gmtime", "localtime", "rand", "strerror", "getenv"}

    def visit_FuncCall(self, node):
        if isinstance(node.name, c_ast.ID):
            func = node.name.name
            if func in self._unsafe_funcs:
                self._violations.append({
                    "rule": self.id,
                    "message": f"Use of non-thread-safe function '{func}' (line {node.coord.line})"
                })
        self.generic_visit(node)
