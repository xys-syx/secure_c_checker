import argparse
from pathlib import Path                     
from parser import c_parser
from checker import checker
from report import console_report, json_report
from core.rules import misra, cert


def main():
    parser = argparse.ArgumentParser(description="c_analyzer")
    parser.add_argument("file", help="Path to the C source file")
    parser.add_argument("--misra", action="store_true",
                        help="Enable MISRA rule-set checking")
    parser.add_argument("--cert", action="store_true",
                        help="Enable CERT rule-set checking")
    parser.add_argument("--format", choices=["console", "json"], default="console",
                        help="Output format (console | json), default is console")
    args = parser.parse_args()


    if not args.misra and not args.cert:
        args.misra = True
        args.cert = True

    src_path = Path(args.file)
    with src_path.open(encoding="utf-8") as f:
        code = f.read()

    c_ast = c_parser.CParser().parse_text(code)

    selected_rules = []
    if args.misra:
        selected_rules += misra.RULES
    if args.cert:
        selected_rules += cert.RULES

    c_checker = checker.Checker(selected_rules)
    violations = c_checker.run(c_ast, code=code, filename=str(src_path))

    reporter = (console_report.ConsoleReporter()
                if args.format == "console"
                else json_report.JSONReporter())
    reporter.output(violations)


if __name__ == "__main__":
    main()
