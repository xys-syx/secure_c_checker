import re
from pycparser import c_ast
from core.rule import Rule
from core.rules.cert.sig31c import NodeCollector

class MEM32C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "MEM32-C"
        self.name = "Detect and handle memory allocation errors"
        self._violations = []
        self._alloc_ptrs = {}

    def visit_Assignment(self, node):
        if node.op == '=' and isinstance(node.rvalue, c_ast.FuncCall):
            func_name = node.rvalue.name.name if isinstance(node.rvalue.name, c_ast.ID) else ""
            if func_name in {"malloc", "calloc", "realloc"}:
                if isinstance(node.lvalue, c_ast.ID):
                    var_name = node.lvalue.name
                    self._alloc_ptrs[var_name] = {"checked": False, "line": node.coord.line}
        self.generic_visit(node)

    def visit_If(self, node):
        cond_ids = []
        node.cond.visit(NodeCollector(c_ast.ID, cond_ids))
        for identifier in cond_ids:
            var = identifier.name
            if var in self._alloc_ptrs:
                self._alloc_ptrs[var]["checked"] = True
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if node.op == '*' and isinstance(node.expr, c_ast.ID):
            var = node.expr.name
            if var in self._alloc_ptrs and not self._alloc_ptrs[var]["checked"]:
                self._violations.append({
                    "rule": self.id,
                    "message": f"Pointer '{var}' from malloc at line {self._alloc_ptrs[var]['line']} used without null-check (line {node.coord.line})"
                })
        self.generic_visit(node)

    def visit_FuncCall(self, node):
        if isinstance(node.name, c_ast.ID):
            func = node.name.name
            for arg in node.args.exprs if node.args else []:
                if isinstance(arg, c_ast.ID):
                    var = arg.name
                    if var in self._alloc_ptrs and not self._alloc_ptrs[var]["checked"] and func not in {"free"}:
                        self._violations.append({
                            "rule": self.id,
                            "message": f"Pointer '{var}' from malloc at line {self._alloc_ptrs[var]['line']} passed to {func}() without null-check (line {node.coord.line})"
                        })
        self.generic_visit(node)
