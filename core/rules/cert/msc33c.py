import re
from core.rule import Rule

# secure_c_checker/rules/cert/msc33c.py
import re
from core.rule import Rule  # <-- adjust this import path based on your setup

class MSC33C(Rule):
    """CERT MSC33-C: Do not use unsafe functions"""
    def __init__(self):
        super().__init__()
        self.id = "MSC33-C"
        self.name = "禁止使用不安全函数"
        self.description = "检测并禁止使用不安全的库函数 (如 strcpy/strcat/sprintf/gets 等)"
        self._banned_funcs = ["gets", "strcpy", "strcat", "sprintf", "scanf"]
        pattern_str = r'\b(?:' + '|'.join(self._banned_funcs) + r')\s*\('
        self._pattern = re.compile(pattern_str)

    def analyze(self, code: str, filename: str):
        for lineno, line in enumerate(code.splitlines(), start=1):
            if self._pattern.search(line):
                self.report_violation(
                    filename, lineno,
                    f"不安全函数调用: {line.strip()}"
                )
