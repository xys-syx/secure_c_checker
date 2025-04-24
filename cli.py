import argparse

from parser import c_parser
from checker import checker
from report import console_report, json_report
from rules import misra, cert

def main():
    parser = argparse.ArgumentParser(description="c_analyzer")
    parser.add_argument("file", help="Path to the C source file")
    parser.add_argument("--misra", action="store_true", help="Enable MISRA Rule Set Checking")
    parser.add_argument("--cert", action="store_true", help="Enable CERT Rule Set Checking")
    parser.add_argument("--format", choices=["console", "json"], default="console", 
                        help="Output format（console or json），default mode is console")
    args = parser.parse_args()

    
    if not args.misra and not args.cert:
        args.misra = True
        args.cert = True


    c_code_ast = c_parser.CParser().parse_file(args.file)


    selected_rules = []
    if args.misra:
        selected_rules += misra.RULES 
    if args.cert:
        selected_rules += cert.RULES


    c_checker = checker.Checker(selected_rules)
    violations = c_checker.run(c_code_ast)


    if args.format == "console":
        reporter = console_report.ConsoleReporter()
    else:  # args.format == "json"
        reporter = json_report.JSONReporter()
    reporter.output(violations)

if __name__ == "__main__":
    main()