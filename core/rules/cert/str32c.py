import re
from pycparser import c_ast
from core.rule import Rule
class STR32C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "STR32-C"
        self.name = "Do not pass non-null-terminated sequence to string functions"
        self._violations = []
        self._non_terminated_buffers = set()

    def visit_FuncCall(self, node):
        if isinstance(node.name, c_ast.ID):
            func = node.name.name
            if func == "strncpy":
                if node.args and len(node.args.exprs) >= 3:
                    dest, src, n = node.args.exprs[0], node.args.exprs[1], node.args.exprs[2]
                    if isinstance(n, c_ast.UnaryOp) and n.op == 'sizeof':
                        if isinstance(n.expr, c_ast.ID) and isinstance(dest, c_ast.ID):
                            if n.expr.name == dest.name:
                                self._non_terminated_buffers.add(dest.name)
            string_funcs = {"strcpy", "strcat", "strcmp", "strlen", "printf", "puts", "fputs", "sprintf", "snprintf"}
            if func in string_funcs:
                for arg in node.args.exprs if node.args else []:
                    if isinstance(arg, c_ast.ID) and arg.name in self._non_terminated_buffers:
                        self._violations.append({
                            "rule": self.id,
                            "message": f"Possible use of non-null-terminated buffer '{arg.name}' in {func}() (line {node.coord.line})"
                        })
        self.generic_visit(node)
