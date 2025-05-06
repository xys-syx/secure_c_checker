import re
from pycparser import c_ast
from core.rule import Rule


class STR31C(Rule, c_ast.NodeVisitor):

    _copy_funcs = {"strcpy", "strcat", "memcpy"}
    _sprintf_funcs = {"sprintf"}
    _scanf_funcs = {"scanf", "fscanf", "sscanf"}
    _gets_funcs = {"gets"}

    def __init__(self):
        super().__init__()
        self.id = "STR31-C"
        self.name = "Sufficient storage for strings"
        self._arrays = {}
        self.filename = "<stdin>"

    def check(self, ast, filename="<unknown>", tainted_vars=None):
        self._violations = []
        self._arrays.clear()
        self.filename = filename
        self.visit(ast)
        return self._violations

    def _report(self, coord, msg):
        line = coord.line if coord else 0
        self._violations.append({
            "file": self.filename,
            "line": line,
            "rule": self.id,
            "severity": "HIGH",
            "description": "[STRING-BOUNDS][OVERFLOW] " + msg
        })

    @staticmethod
    def _is_char_array(ty):
        return isinstance(ty, c_ast.TypeDecl) and \
               isinstance(ty.type, c_ast.IdentifierType) and \
               ty.type.names == ["char"]

    @staticmethod
    def _const_int(expr):
        if isinstance(expr, c_ast.Constant) and expr.type == "int":
            try:
                return int(expr.value, 0)
            except ValueError:
                return None
        return None

    def visit_Decl(self, node):
        # char buf[N];
        if isinstance(node.type, c_ast.ArrayDecl):
            arr = node.type
            if self._is_char_array(arr.type):
                sz = self._const_int(arr.dim)
                if sz is not None:
                    self._arrays[node.name] = sz
                    # overflow in literal initialiser?
                    if isinstance(node.init, c_ast.Constant) and node.init.type == "string":
                        lit_len = len(node.init.value.strip('"'))
                        if sz <= lit_len:
                            self._report(node.coord,
                                         f"{node.name}[{sz}] initialised with "
                                         f'\"{node.init.value.strip()}\" (length {lit_len})')
        self.generic_visit(node)

    def visit_FuncCall(self, node):
        fname = node.name.name if isinstance(node.name, c_ast.ID) else None
        if not fname:
            self.generic_visit(node)
            return

        args = node.args.exprs if node.args else []

        if fname in self._gets_funcs:
            if args and isinstance(args[0], c_ast.ID):
                dest = args[0].name
                self._report(node.coord, f"call to removed/unsafe gets({dest})")
            else:
                self._report(node.coord, "call to removed/unsafe gets()")
            return

        if fname in self._copy_funcs and len(args) >= 2:
            dest, src = args[0], args[1]
            if isinstance(dest, c_ast.ID) and dest.name in self._arrays \
                    and isinstance(src, c_ast.Constant) and src.type == "string":
                size   = self._arrays[dest.name]
                litlen = len(src.value.strip('"'))
                if litlen >= size:
                    self._report(node.coord,
                                 f"{fname} writes {litlen+1} bytes into "
                                 f"{dest.name}[{size}]")
            self.generic_visit(node)
            return

        if fname in self._sprintf_funcs and len(args) >= 2:
            dest, fmt = args[0], args[1]
            if isinstance(dest, c_ast.ID) and dest.name in self._arrays \
                    and isinstance(fmt, c_ast.Constant) and fmt.type == "string":
                unsafe = self._fmt_has_unsafe_s(fmt.value.strip('"'))
                if unsafe:
                    self._report(node.coord,
                                 f"sprintf into {dest.name}[{self._arrays[dest.name]}] "
                                 "with unchecked \"%s\" conversion")
            self.generic_visit(node)
            return

        if fname in self._scanf_funcs and len(args) >= 2:
            fmt_idx = 0 if fname == "scanf" else 1
            fmt = args[fmt_idx]
            if isinstance(fmt, c_ast.Constant) and fmt.type == "string":
                conversions = self._extract_scanf_s(fmt.value.strip('"'))
                arg_i = fmt_idx + 1
                for conv in conversions:
                    if arg_i >= len(args):
                        break
                    dest = args[arg_i]
                    arg_i += 1
                    if conv is None:
                        if isinstance(dest, c_ast.ID) and dest.name in self._arrays:
                            self._report(node.coord,
                                         f"{fname} writes unbounded string into "
                                         f"{dest.name}[{self._arrays[dest.name]}]")
                    else:
                        if isinstance(dest, c_ast.ID) and dest.name in self._arrays:
                            if conv >= self._arrays[dest.name]:
                                self._report(node.coord,
                                             f"{fname} may write {conv+1} bytes into "
                                             f"{dest.name}[{self._arrays[dest.name]}]")
            self.generic_visit(node)
            return

        self.generic_visit(node)

    @staticmethod
    def _fmt_has_unsafe_s(fmt):
        """Return True if the printf-style format has any %s with *no* precision."""
        i, n = 0, len(fmt)
        while i < n:
            if fmt[i] == '%':
                i += 1
                if i < n and fmt[i] == '%':
                    i += 1
                    continue
                has_dot = False
                while i < n and fmt[i] not in "sdiouxXeEfFgGcpaAn%":
                    if fmt[i] == '.':
                        has_dot = True
                    i += 1
                if i < n and fmt[i] == 's':
                    if not has_dot:
                        return True
            else:
                i += 1
        return False

    @staticmethod
    def _extract_scanf_s(fmt):
        pattern = re.compile(r'%(?:\*?)(\d*)s')
        res = []
        i = 0
        while i < len(fmt):
            if fmt[i] == '%':
                if i + 1 < len(fmt) and fmt[i+1] == '%':
                    i += 2
                    continue
                m = pattern.match(fmt, i)
                if m:
                    width_str = m.group(1)
                    res.append(int(width_str) if width_str else None)
                    i = m.end()
                    continue
            i += 1
        return res
