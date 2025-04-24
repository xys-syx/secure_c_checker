"""
CERT rule example: Do not use deprecated function gets() 
(Corresponds to CERT MSC24-C: Do not use deprecated or obsolete functions &#8203;:contentReference[oaicite:5]{index=5})
"""
from pycparser.c_ast import NodeVisitor, ID

class RuleNoDeprecated:
    """CERT Rule MSC24-C: Do not call deprecated functions (e.g. gets)"""
    def __init__(self):
        # 规则编号和描述信息
        self.id = "CERT MSC24-C"
        self.description = "Do not call deprecated functions gets()"

    def check(self, ast):
        """
        Checks if the gets() function was called in the given AST.
        Returns a list of violations, each containing the line number, rule number and violation description.
        """
        issues = []

        class FuncCallVisitor(NodeVisitor):
            def __init__(self):
                self.issues = []
            def visit_FuncCall(self, node):
                if isinstance(node.name, ID) and node.name.name == "gets":
                    line_no = node.coord.line
                    self.issues.append({
                        "line": line_no,
                        "rule": "CERT MSC24-C",
                        "description": "Do not call deprecated functions gets()"
                    })
                self.generic_visit(node)

        visitor = FuncCallVisitor()
        visitor.visit(ast)
        issues.extend(visitor.issues)
        return issues
