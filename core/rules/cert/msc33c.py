import re
from core.rule import Rule

class MSC33C(Rule):
    def __init__(self):
        super().__init__()
        self.id = "MSC33-C"
        self.name = "Prohibit Use of Unsafe Functions"
        self.description = (
            "Detect and prohibit use of unsafe library functions "
            "(e.g., strcpy, strcat, sprintf, gets, scanf, etc.)"
        )
        self._banned_funcs = ["gets", "strcpy", "strcat", "sprintf", "scanf"]
        pattern_str = r'\b(?:' + '|'.join(self._banned_funcs) + r')\s*\('
        self._pattern = re.compile(pattern_str)

    def analyze(self, code: str, filename: str):
        for lineno, line in enumerate(code.splitlines(), start=1):
            if self._pattern.search(line):
                self.report_violation(
                    filename, lineno,
                    f"Unsafe function call: {line.strip()}"
                )

