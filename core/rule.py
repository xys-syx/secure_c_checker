class Rule:
    """
    Base class for CERT and MISRA rules.
    Provides basic metadata fields and violation reporting mechanism.
    """
    def __init__(self):
        self.id = ""
        self.name = ""
        self.description = ""
        self._violations = []

    def analyze(self, code: str, filename: str):
        """
        Main method to override in subclasses.
        Should populate self._violations based on analysis.
        """
        raise NotImplementedError("Subclasses must implement analyze()")

    def report_violation(self, filename, lineno, message):
        """
        Add a new violation to the internal list.
        """
        self._violations.append({
            "file": filename,
            "line": lineno,
            "rule": self.id,
            "description": message
        })

    def get_violations(self):
        """
        Returns the list of violations collected during analysis.
        """
        return self._violations