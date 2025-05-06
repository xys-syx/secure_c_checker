import re
from pycparser import c_ast
from core.rule import Rule

class SIG30C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "SIG30-C"
        self.name = "Call only async-safe functions within signal handlers"
        self._violations = []
        self._handler_funcs = set()
        self._allowed_funcs = {"abort", "_Exit", "quick_exit", "signal"}

    def visit_FuncCall(self, node):
        if isinstance(node.name, c_ast.ID) and node.name.name in {"signal", "sigaction"}:
            if node.args and len(node.args.exprs) >= 2:
                handler = node.args.exprs[1]
                if isinstance(handler, c_ast.ID):
                    self._handler_funcs.add(handler.name)
        self.generic_visit(node)

    def visit_FuncDef(self, node):
        func_name = node.decl.name
        self.generic_visit(node.body)
        if func_name in self._handler_funcs:
            for subnode in node.body.block_items or []:
                if isinstance(subnode, c_ast.FuncCall):
                    call_name = subnode.name.name if isinstance(subnode.name, c_ast.ID) else ""
                    if call_name and call_name not in self._allowed_funcs:
                        self._violations.append({
                            "rule": self.id,
                            "message": f"Illegal call to '{call_name}' in signal handler '{func_name}' (line {subnode.coord.line})"
                        })

