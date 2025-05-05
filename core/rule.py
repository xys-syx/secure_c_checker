class Rule:
    def __init__(self):
        self.id = ""
        self.name = ""
        self.description = ""
        self._violations = []

    def analyze(self, code: str, filename: str):
        #raise NotImplementedError("Subclasses must implement analyze()")
        return NotImplementedError

    def report_violation(self, filename, lineno, message):
        self._violations.append({
            "file": filename,
            "line": lineno,
            "rule": self.id,
            "description": message
        })

    def get_violations(self):
        return self._violations
    
    def check(self, ast, filename: str, tainted_vars=None):
        raise NotImplementedError