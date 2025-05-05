from core.rule import Rule
from pycparser import c_ast, c_parser
from pycparser.c_ast import ID, Constant, NodeVisitor

class FIO30C(Rule, NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "FIO30-C"
        self.name = "Exclude user input from format strings"
        self._violations = []

        self._fmt_funcs = {
            "printf": 0, "wprintf": 0, "vprintf": 0,
            "fprintf": 1, "fwprintf": 1, "vfprintf": 1, "dprintf": 1,
            "sprintf": 1, "vsprintf": 1,
            "snprintf": 2, "vsnprintf": 2,
            "swprintf": 2,
            "syslog": 1 
        }

        self._tainted = set()

    def analyze(self, code: str, filename="<unknown>", tainted_vars=None):
        ast = c_parser.CParser().parse(code)
        return self.check(ast, filename, tainted_vars)

    def check(self, ast, filename="<unknown>", tainted_vars=None):
        self._violations.clear()
        self._tainted = set(tainted_vars or [])
        self.filename = filename
        self.visit(ast)
        return self._violations
    
    def _expr_is_tainted(self, expr):
        if expr is None:
            return False
        if isinstance(expr, ID):
            return expr.name in self._tainted
        if isinstance(expr, c_ast.ArrayRef):
            return (isinstance(expr.name, ID) and expr.name.name == "argv") or \
                   self._expr_is_tainted(expr.name)
        if isinstance(expr, c_ast.FuncCall):
            return isinstance(expr.name, ID) and expr.name.name == "getenv"
        for _, child in expr.children():
            if self._expr_is_tainted(child):
                return True
        return False
    
    def visit_FuncDef(self, node):
        prev = self._tainted.copy()
        if node.decl.type.args:
            for p in node.decl.type.args.params:
                if isinstance(p, c_ast.Decl) and p.name:
                    self._tainted.add(p.name)
        self.visit(node.body)
        self._tainted = prev

    def visit_Decl(self, node):
        # skip function prototypes
        if isinstance(node.type, c_ast.FuncDecl):
            return
        # detect char[] = "literal"
        if node.init and isinstance(node.init, Constant) and node.init.type == 'string':
            # literal initialiser – NOT tainted
            pass
        else:
            if node.init:
                self.visit(node.init)
                if node.name and self._expr_is_tainted(node.init):
                    self._tainted.add(node.name)
    
    def visit_FuncCall(self, node):
        fname = node.name.name if isinstance(node.name, ID) else None
        if fname in {"sprintf", "snprintf", "vsprintf", "vsnprintf", "swprintf"}:
            args = node.args.exprs if node.args else []
            if args:
                dest = args[0]
                start = 1 if fname in {"sprintf", "vsprintf"} else 2
                if any(self._expr_is_tainted(a) for a in args[start:]):
                    if isinstance(dest, ID):
                        self._tainted.add(dest.name)
    
        star_tainted = False
        if fname in self._fmt_funcs and node.args:
            args = node.args.exprs
            fmt_arg = args[self._fmt_funcs[fname]] if \
                        self._fmt_funcs[fname] < len(args) else None
            if isinstance(fmt_arg, Constant) and '*' in fmt_arg.value:
                star_idx = self._fmt_funcs[fname] + 1
                if star_idx < len(args):
                    star_tainted = self._expr_is_tainted(args[star_idx])
        
        if fname in self._fmt_funcs:
            args = node.args.exprs if node.args else []
            fmt_idx = self._fmt_funcs[fname]
            if fmt_idx < len(args):
                fmt_arg = args[fmt_idx]
                is_literal = isinstance(fmt_arg, Constant) and fmt_arg.type == "string"

                violation = False
                severity = "LOW"
                if not is_literal:
                    violation = True
                    severity  = "HIGH" if self._expr_is_tainted(fmt_arg) else "MEDIUM"
                elif star_tainted:
                    violation = True
                    severity  = "HIGH"
                if violation:
                    srcs, vars_ = self._collect_sources(fmt_arg)
                    if star_tainted:
                        srcs.add("width/precision*")
                    self._violations.append({
                        "file": self.filename,
                        "line": node.coord.line,
                        "rule": self.id,
                        "severity": severity,
                        "tainted_sources": sorted(srcs),
                        "tainted_vars":    sorted(vars_),
                        "description": "Non-constant or tainted format string in "
                                       f"{fname}()",
                        "recommendation": (
                           "Keep format strings literal. Pass user data via "
                           "arguments, or use fputs/puts when no formatting needed."
                        )
                    })
        self.generic_visit(node)

    def _collect_sources(self, expr):
        srcs, vars_ = set(), set()
        def walk(e):
            if isinstance(e, ID) and e.name in self._tainted:
                vars_.add(e.name)
            elif isinstance(e, c_ast.ArrayRef):
                if isinstance(e.name, ID) and e.name.name == "argv":
                    srcs.add("argv")
            elif isinstance(e, c_ast.FuncCall):
                if isinstance(e.name, ID) and e.name.name == "getenv":
                    srcs.add(f'env({e.args.exprs[0].value.strip("\"")})')
            for _, ch in e.children():
                walk(ch)
        walk(expr)
        for v in list(vars_):
            if v == "argv":
                srcs.add("argv"); vars_.discard("argv")
        return srcs, vars_

