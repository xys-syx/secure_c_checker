from core.rule import Rule
from pycparser import c_ast
from pycparser.c_ast import NodeVisitor, ID, Constant, UnaryOp, BinaryOp

class MEM34C(Rule, NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "MEM34-C"
        self.name = "Only free dynamically allocated memory"
        self.description = "Detects calls to free() with pointers that were not allocated via malloc/calloc/realloc, or that are not the start of an allocated block."
        self._ptr_origin = {}
        self._param_ptrs = set()

    def analyze(self, ast, filename="<unknown>"):
        if ast is None:
            return []
        self._ptr_origin.clear()
        self._param_ptrs.clear()
        self.filename = filename
        self.visit(ast)
        return self._violations

    def visit_FuncDef(self, node):
        prev_param_ptrs = self._param_ptrs.copy()
        self._param_ptrs.clear()
        if node.decl.type.args:
            for param in node.decl.type.args.params:
                if isinstance(param, c_ast.Decl) and isinstance(param.type, (c_ast.PtrDecl, c_ast.ArrayDecl)):
                    self._param_ptrs.add(param.name)
        self.visit(node.body)
        self._param_ptrs = prev_param_ptrs

    def visit_Decl(self, node):
        if isinstance(node.type, c_ast.PtrDecl):
            name = node.name
            if name not in self._ptr_origin:
                self._ptr_origin[name] = "unknown"
            if node.init:
                self.visit(node.init)
                origin = self._infer_origin_from_expr(node.init)
                if origin:
                    self._ptr_origin[name] = origin
        if isinstance(node.type, c_ast.ArrayDecl):
            if not self._in_function():
                self._ptr_origin[node.name] = "static"
        if node.init:
            self.visit(node.init)
        self.generic_visit(node)

    def visit_Assignment(self, node):
        if isinstance(node.lvalue, c_ast.ID):
            dest = node.lvalue.name
            origin = self._infer_origin_from_expr(node.rvalue)
            if origin:
                self._ptr_origin[dest] = origin
            self.generic_visit(node)

    def visit_FuncCall(self, node):
        func_name = node.name.name if isinstance(node.name, c_ast.ID) else None
        if func_name == "free":
            arg = node.args.exprs[0] if node.args and node.args.exprs else None
            if arg:
                if self._is_null_pointer(arg):
                    return
                if not isinstance(arg, c_ast.ID):
                    self._report(node.coord, "HIGH", "free() called with invalid expression (not a malloc-allocated pointer)")
                    return
                ptr_name = arg.name
                if ptr_name in self._param_ptrs and ptr_name not in self._ptr_origin:
                    return
                origin = self._ptr_origin.get(ptr_name, "unknown")
                if origin != "dynamic":
                    self._report(node.coord, "HIGH",
                                 f"free() called on pointer '{ptr_name}' which is not a heap allocation (origin: {origin})")
            return
        # if node.args:
        #     for expr in node.args.exprs:
        #         self.visit(expr)
        self.generic_visit(node)

    def _infer_origin_from_expr(self, expr):
        if expr is None:
            return None
        if isinstance(expr, c_ast.FuncCall):
            if isinstance(expr.name, c_ast.ID) and expr.name.name in ("malloc", "calloc", "realloc"):
                return "dynamic"
            return "unknown"
        if isinstance(expr, c_ast.UnaryOp) and expr.op == '&':
            return "static"
        if isinstance(expr, c_ast.Constant) and expr.type == 'string':
            return "static"
        if isinstance(expr, c_ast.ID):
            src_name = expr.name
            return self._ptr_origin.get(src_name, "unknown")
        if isinstance(expr, c_ast.BinaryOp) and expr.op in ('+', '-'):
            base_origin = None
            if isinstance(expr.left, c_ast.ID) and isinstance(expr.right, c_ast.Constant):
                base_origin = self._ptr_origin.get(expr.left.name, "unknown")
            elif isinstance(expr.left, c_ast.Constant) and isinstance(expr.right, c_ast.ID):
                base_origin = self._ptr_origin.get(expr.right.name, "unknown")
            elif isinstance(expr.left, c_ast.ID) and isinstance(expr.right, c_ast.ID):
                base_origin_left = self._ptr_origin.get(expr.left.name, "unknown")
                base_origin_right = self._ptr_origin.get(expr.right.name, "unknown")
                base_origin = base_origin_left if base_origin_left != "unknown" else base_origin_right
            else:
                base_origin = "unknown"
            if base_origin == "dynamic":
                return "offset"
            elif base_origin in ("static", "unknown"):
                return base_origin
        return None

    def _is_null_pointer(self, expr):
        return (isinstance(expr, c_ast.Constant) and expr.type == 'int' and expr.value == '0') or \
               (isinstance(expr, c_ast.ID) and expr.name == "NULL")

    def _in_function(self):
        return len(self._param_ptrs) > 0

    def _report(self, coord, severity, description):
        self._violations.append({
            "file": self.filename,
            "line": coord.line if coord else 0,
            "rule": "MEM34-C",
            "severity": severity,
            "description": description
        })
