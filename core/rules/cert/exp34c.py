import re
from pycparser import c_ast
from core.rule import Rule

class EXP34C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "EXP34-C"
        self.name = "Do not dereference null pointers"
        self._violations = []
        self._null_ptrs = set()

    def visit_Assignment(self, node):
        if node.op == '=':
            if isinstance(node.lvalue, c_ast.ID):
                var_name = node.lvalue.name
                if isinstance(node.rvalue, c_ast.Constant) and node.rvalue.value == '0':
                    self._null_ptrs.add(var_name)
                if isinstance(node.rvalue, c_ast.ID) and node.rvalue.name == 'NULL':
                    self._null_ptrs.add(var_name)
        self.generic_visit(node)

    def visit_FuncCall(self, node):
        func_name = node.name.name if isinstance(node.name, c_ast.ID) else ""
        if func_name in {"malloc", "calloc"}:
            if isinstance(self._parent, c_ast.UnaryOp) and self._parent.op == '*':
                self._report(node, "Direct dereference of malloc return")
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if node.op == '*':
            if isinstance(node.expr, c_ast.ID):
                if node.expr.name in self._null_ptrs:
                    self._report(node, f"Dereference of null pointer '{node.expr.name}'")
            if isinstance(node.expr, c_ast.Constant) and node.expr.value == '0':
                self._report(node, "Dereference of literal null (0) pointer")
        self.generic_visit(node)

    def _report(self, node, desc):
        self._violations.append({
            "rule": self.id,
            "message": f"{desc} at line {node.coord.line}"
        })

    def generic_visit(self, node):
        for child_name, child in node.children():
            self._parent = node
            self.visit(child)
