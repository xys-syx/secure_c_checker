class Checker:
    def __init__(self, rules):
        self.rules = [rule() for rule in rules]

    def run(self, ast, code=None, filename="<unknown>"):
        results = []
        if ast is None:
            return results

        for rule in self.rules:
            if hasattr(rule, "analyze") and code:
                rule.analyze(code, filename)
            if hasattr(rule, "check") and ast:
                rule.check(ast, filename)
            results.extend(rule.get_violations())
        return results
