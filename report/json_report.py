"""
JSON Reporting Module:
Responsible for outputting the violation results in JSON format for easy machine reading or further processing.
"""
import json

class JSONReporter:
    def output(self, violations):
        print(json.dumps(violations, ensure_ascii=False, indent=4))
