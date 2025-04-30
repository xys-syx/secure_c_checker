"""
CERT ENV33-C  – Do NOT invoke system-spawning functions
Detect calls to system(), popen(), execl(), execvp(), etc.
"""
import re
from core.rule import Rule

class ENV33C(Rule):
    """CERT ENV33-C: forbid use of system() and similar process spawners."""
    def __init__(self):
        super().__init__()
        self.id = "CERT ENV33-C"
        self.name = "Forbid process-spawning APIs"
        self.description = (
            "Do not call system()/popen()/exec*() family – "
            "they are dangerous and violate ENV33-C."
        )

        banned = [
            "system", "popen", "pclose", "execl", "execlp", "execle",
            "execv", "execvp", "execvpe", "execve"
        ]

        pattern = r"\b(?:{})\s*\(".format("|".join(banned))
        self._regex = re.compile(pattern)

    def analyze(self, code: str, filename: str):
        for lineno, line in enumerate(code.splitlines(), 1):
            if self._regex.search(line):
                self.report_violation(
                    filename,
                    lineno,
                    f"dangerous process-spawning call: {line.strip()}"
                )
