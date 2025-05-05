from parser import c_parser
from core.rule import Rule

class Checker:
    def __init__(self, rules):
        self.rules = [rule() for rule in rules]

    def run(self, ast, code=None, filename="<unknown>"):
        results = []
        if ast is None:
            return results

        tainted_vars = c_parser.last_parser.tainted_vars if hasattr(c_parser, 'last_parser') else None


        for rule in self.rules:
            used = False
            # if hasattr(rule, "analyze") and code:
            #     try:
            #         rule.analyze(code, filename, tainted_vars=tainted_vars)
            #     except TypeError:
            #         rule.analyze(code, filename)
            if hasattr(rule, "check") and ast:
                if rule.__class__.check is not Rule.check:
                    try:
                        rule.check(ast, filename, tainted_vars=tainted_vars)
                    except TypeError:
                        rule.check(ast, filename)
                    used = True
            if not used and hasattr(rule, "analyze") and code is not None:
                try:
                    rule.analyze(code, filename, tainted_vars=tainted_vars)
                except TypeError:
                    rule.analyze(code, filename)
            results.extend(rule.get_violations())
        return results