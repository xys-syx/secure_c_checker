"""
Console Reporting Module:
Responsible for outputting the results of a violation to the console in readable text.
"""
class ConsoleReporter:
    """Output the results of the check to the console in text format"""
    def output(self, violations):
        if not violations:
            print("No violations found.")
            return
        for issue in violations:
            line = issue.get("line")
            rule = issue.get("rule")
            description = issue.get("description")
            print(f"Line {line}: [{rule}] {description}")
