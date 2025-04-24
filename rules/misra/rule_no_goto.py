"""
MISRA rule example: prohibit the use of the goto statement (corresponds to MISRA C:2012 rule 15.1&#8203;:contentReference[oaicite:4]{index=4})
"""
from pycparser.c_ast import NodeVisitor

class RuleNoGoto:
    """MISRA Rule 15.1: goto statement not allowed"""
    def __init__(self):
        self.id = "MISRA 15.1"
        self.description = "The use of the goto statement is prohibited."

    def check(self, ast):
        """
        Checks if the goto statement is used in the given AST.
        Returns a list of violations, each containing a line number, rule number and violation description.
        """
        issues = []

        class GotoVisitor(NodeVisitor):
            def __init__(self):
                self.issues = []
            def visit_Goto(self, node):
                line_no = node.coord.line
                self.issues.append({
                    "line": line_no,
                    "rule": "MISRA 15.1",
                    "description": "The use of the goto statement is prohibited."
                })

        visitor = GotoVisitor()
        visitor.visit(ast)

        issues.extend(visitor.issues)
        return issues
