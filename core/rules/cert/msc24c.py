import re
from core.rule import Rule
from pycparser.c_ast import NodeVisitor, ID

class MSC24C(Rule):
    def __init__(self):
        super().__init__()
        self.id = "MSC24-C"
        self.name = "Forbit using deprecated function"
        self.description = "Do not call deprecated functions gets()"
        self.pattern = re.compile(r'\bgets\s*\(')

    # def check(self, ast):
    #     issues = []

    #     class FuncCallVisitor(NodeVisitor):
    #         def __init__(self):
    #             self.issues = []
    #         def visit_FuncCall(self, node):
    #             if isinstance(node.name, ID) and node.name.name == "gets":
    #                 line_no = node.coord.line
    #                 self.issues.append({
    #                     "line": line_no,
    #                     "rule": "CERT MSC24-C",
    #                     "description": "Do not call deprecated functions gets()"
    #                 })
    #             self.generic_visit(node)

    #     visitor = FuncCallVisitor()
    #     visitor.visit(ast)
    #     issues.extend(visitor.issues)
    #     return issues
    def analyze(self, code: str, filename: str):
        for lineno, line in enumerate(code.splitlines(), start=1):
            if self.pattern.search(line):
                self.report_violation(
                    filename,
                    lineno,
                    f"unsafe function call: {line.strip()}"
                )
