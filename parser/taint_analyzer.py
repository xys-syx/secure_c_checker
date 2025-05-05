from pycparser import c_parser, c_ast

class TaintAnalyzer(c_ast.NodeVisitor):
    def __init__(self):
        self._taint_vars = set()
        self._current_tainted = None
        self._scope_stack = []

    def visit_FuncDef(self, node):
        self._scope_stack.append(self._current_tainted)
        self._current_tainted = set()

        if node.decl.type.args:
            for param in node.decl.type.args.params:
                if isinstance(param, c_ast.Decl):
                    self._current_tainted.add(param.name)
                    self._taint_vars.add(param.name)

        self.visit(node.body)
        self._current_tainted = self._scope_stack.pop()

    def visit_Assignment(self, node):
        self.generic_visit(node)
        if node.op == '=' and isinstance(node.lvalue, c_ast.ID):
            target = node.lvalue.name
            if self._expr_is_tainted(node.rvalue):
                self._current_tainted.add(target)
                self._taint_vars.add(target)
    
    def visit_Decl(self, node):
        self.generic_visit(node)
        if node.init is not None:
            var_name = node.name
            if self._expr_is_tainted(node.init):
                self._current_tainted.add(var_name)
                self._taint_vars.add(var_name)

    def _expr_is_tainted(self, expr):
        if isinstance(expr, c_ast.ID):
            return expr.name in self._current_tainted
        if isinstance(expr, c_ast.Constant):
            return False
        if isinstance(expr, c_ast.FuncCall):
            if isinstance(expr.name, c_ast.ID) and expr.name.name == 'getenv':
                return True
            return False
        if isinstance(expr, (c_ast.BinaryOp, c_ast.UnaryOp, c_ast.Cast)):
            return any(self._expr_is_tainted(child) for child in expr.children())
        if isinstance(expr, (c_ast.ArrayRef, c_ast.StructRef)):
            return self._expr_is_tainted(expr.name)
        return False
    
