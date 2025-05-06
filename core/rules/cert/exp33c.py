from core.rule import Rule
from pycparser import c_ast
from pycparser.c_ast import NodeVisitor, ID

class EXP33C(Rule, NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "EXP33-C"
        self.name = "Do not read uninitialized memory"
        self.description = "Flags any use of variables or memory that have not been initialized before use."
        self._initialized_vars = set()
        self._declared_vars = set()
        self._global_vars = set()
        self._param_vars = set()

    def analyze(self, ast, filename="<unknown>"):
        if ast is None:
            return []
        self._initialized_vars.clear()
        self._declared_vars.clear()
        self._global_vars.clear()
        self._param_vars.clear()
        self.filename = filename
        self.visit(ast)
        return self._violations

    def visit_Decl(self, node):
        if isinstance(node.type, c_ast.TypeDecl) and not self._in_function():
            self._global_vars.add(node.name)
            if node.init is not None or 'static' in (node.storage or []):
                self._initialized_vars.add(node.name)
            else:
                self._initialized_vars.add(node.name)
        if isinstance(node.type, c_ast.TypeDecl) and self._in_function():
            self._declared_vars.add(node.name)
            if node.init is not None:
                self.visit(node.init)
                self._initialized_vars.add(node.name)
        if node.init:
            self.visit(node.init)

    def visit_FuncDef(self, node):
        prev_declared = self._declared_vars.copy()
        prev_initialized = self._initialized_vars.copy()
        prev_params = self._param_vars.copy()
        # Clear local tracking
        self._declared_vars = set()
        self._initialized_vars = set()
        self._param_vars = set()
        if node.decl.type.args:
            for param in node.decl.type.args.params:
                if isinstance(param, c_ast.Decl):
                    self._param_vars.add(param.name)
                    self._declared_vars.add(param.name)
                    self._initialized_vars.add(param.name)
        self.visit(node.body)
        self._declared_vars = prev_declared
        self._initialized_vars = prev_initialized
        self._param_vars = prev_params

    def visit_Assignment(self, node):
        if node.op != '=':
            self.visit(node.lvalue)
        self.visit(node.rvalue)
        if isinstance(node.lvalue, c_ast.ID):
            var_name = node.lvalue.name
            self._declared_vars.add(var_name)
            self._initialized_vars.add(var_name)
        else:
            pass

    def visit_ID(self, node):
        name = node.name
        if name in self._declared_vars or name in self._param_vars or name in self._global_vars:
            if name not in self._initialized_vars:
                self._report(node.coord, "HIGH", f"Use of uninitialized variable '{name}'")

    def visit_UnaryOp(self, node):
        if node.op == '*':
            if isinstance(node.expr, c_ast.ID):
                ptr = node.expr.name
                if ptr not in self._initialized_vars:
                    self._report(node.coord, "HIGH",
                                 f"Dereference of uninitialized pointer '{ptr}'")
        elif node.op in ('++', '--'):
            if isinstance(node.expr, c_ast.ID):
                var = node.expr.name
                if var not in self._initialized_vars:
                    self._report(node.coord, "HIGH",
                                 f"Use of uninitialized variable '{var}'")
                self._initialized_vars.add(var)
        self.generic_visit(node)

    def visit_BinaryOp(self, node):
        self.generic_visit(node)

    def visit_FuncCall(self, node):
        self.generic_visit(node)
    def _in_function(self):
        return len(self._param_vars) > 0 or len(self._declared_vars) > 0

    def _report(self, coord, severity, description):
        self._violations.append({
            "file": self.filename,
            "line": coord.line if coord else 0,
            "rule": "EXP33-C",
            "severity": severity,
            "description": description
        })
