import re
from pycparser import c_ast
from core.rule import Rule
class FIO45C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "FIO45-C"
        self.name = "Avoid TOCTOU race conditions while accessing files"
        self._violations = []
        self._checked_files = set()

    def visit_FuncCall(self, node):
        if isinstance(node.name, c_ast.ID):
            func = node.name.name
            if func in {"access", "stat", "lstat", "fstat"}:
                if node.args and len(node.args.exprs) > 0:
                    arg = node.args.exprs[0]
                    if isinstance(arg, c_ast.Constant) and arg.type == 'string':
                        self._checked_files.add(arg.value)
                    elif isinstance(arg, c_ast.ID):
                        self._checked_files.add(arg.name)
            if func in {"open", "fopen"}:
                if node.args and len(node.args.exprs) > 0:
                    arg = node.args.exprs[0]
                    file_id = None
                    if isinstance(arg, c_ast.Constant) and arg.type == 'string':
                        file_id = arg.value
                    elif isinstance(arg, c_ast.ID):
                        file_id = arg.name
                    if file_id and file_id in self._checked_files:
                        self._violations.append({
                            "rule": self.id,
                            "message": f"TOCTOU risk: {func} on previously checked file '{file_id}' (line {node.coord.line})"
                        })
        self.generic_visit(node)
