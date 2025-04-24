"""
Checker Module:
Responsible for checking all selected rules of the AST application and collecting violation results.
"""
class Checker:
    """Apply a set of rules to the AST's inspector"""
    def __init__(self, rules):
        """
        Initialize the Checker instance.
        The argument rules is a list of rule classes (each rule class should provide a check(ast) method).
        """

        self.rules = [rule() for rule in rules]

    def run(self, ast):
        """
        Run Inspector: Applies all rule inspections to the AST.
        Returns a list of all violations (each violation is a dictionary with line number, rule number, description).
        """
        results = []
        if ast is None:
            return results

        for rule in self.rules:
            issues = rule.check(ast)
            results.extend(issues)
        return results
