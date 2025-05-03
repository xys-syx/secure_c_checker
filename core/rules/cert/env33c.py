from core.rule import Rule
from pycparser import c_parser, c_ast
from pycparser.c_ast import NodeVistor, ID, Constant

class ENV33C(Rule):
    def __init__(self):
        super().__init__()
        self.rule_id = "ENV33-C"
        #self._violations = []
        self.name = "Do not call system() or equivalent"
        self.description = ("Detects usage of dangerous process-spawning functions "
                            "like system(), popen(), execlp(), execvp(), etc., as per CERT ENV33-C")
        self._dangerous_funcs = {"system", "popen", "_popen", "_wpopen", "execlp", "execvp"}
        self.current_file = None
    
    def analyze(self, ast, filename: str = "<unknown>"):
        if ast is None:
            return []
        self.current_file = filename
        self.visit(ast)
        return self._violations
    

    def visit_FuncDef(self, node):
        # entering a function: initialize tainted set with parameters
        prev_tainted = self._tainted_vars
        self._tainted_vars = set()
        # Mark all function parameters as tainted
        if node.decl.type.args:
            for param in node.decl.type.args.params:
                if isinstance(param, c_ast.Decl):
                    self._tainted_vars.add(param.name)
        self.visit(node.body)
        self._tainted_vars = prev_tainted

    def visit_Assignment(self, node):
        self.generic_visit(node)
        if node.op == '=':
            if isinstance(node.lvalue, c_ast.ID):
                target_var = node.lvalue.name
                if self._expr_is_tainted(node.rvalue):
                    self._tainted_vars.add(target_var)

    def visit_Decl(self, node):
        self.generic_visit(node)
        if node.init is not None:
            if isinstance(node.type, c_ast.TypeDecl):
                var_name = node.name
                if self._expr_is_tainted(node.init):
                    self._tainted_vars.add(var_name)

    def visit_FuncCall(self, node):
        self.generic_visit(node)
        func_name = None
        if isinstance(node.name, c_ast.ID):
            func_name = node.name.name
        if func_name and func_name in self._banned_funcs:
            arg = node.args.exprs[0]
            if self._is_null_pointer(arg):
                return
            
        severity = "LOW"
        tainted_sources = []
        if node.args:
            args = node.args.exprs
        else:
            args = []
        tainted_found = False
        all_const = True
        for expr in args:
            if self._expr_is_tainted(expr):
                tainted_found = True
                tainted_vars = self._get_tainted_vars_in_expr(expr)
                tainted_sources.extend(tainted_vars)
            if not self._expr_is_constant(expr):
                all_const = False
        if tainted_found:
            severity = "HIGH"
        elif not all_const:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        recommendation = self._make_recommendation(func_name)

        self._violations.append({
            "file": self.filename,
            "line": node.coord.line,
            "rule": "ENV33-C",
            "severity": severity,
            "tainted": severity,
            "tainted_sources": tainted_sources,
            "description": f"Forbidden call to {func_name}()",
            "recommendation": recommendation
        })

    def _is_null_pointer(self, expr):
        if isinstance(expr, c_ast.Constant) and expr.type == 'int' and expr.value == '0':
            return True
        if isinstance(expr, c_ast.Constant) and expr.type == 'char' and expr.value == '0':
            return True
        if isinstance(expr, c_ast.ID) and expr.name == "NULL":
            return True
        if isinstance(expr, c_ast.Cast):
            return self._is_null_pointer(expr.expr)
        return False
    
    def _expr_is_constant(self, expr):
        if isinstance(expr, c_ast.Constant):
            return True
        if isinstance(expr, c_ast.ID):
            return False
        if isinstance(expr, (c_ast.BinaryOp, c_ast.UnaryOp, c_ast.FuncCall,
                             c_ast.Cast, c_ast.ArrayRef, c_ast.StructRef)):
            return False
        return False
    
    def _expr_is_tainted(self, expr):
        if isinstance(expr, c_ast.ID):
            return expr.name in self._tainted_vars
        if isinstance(expr, c_ast.Constant):
            return False
        if isinstance(expr, c_ast.FuncCall):
            # getenv() return is tainter
            if isinstance(expr.name, c_ast.ID) and expr.name.name == "getenv":
                return True
            return False
        if isinstance(expr, c_ast.BinaryOp):
            return self._expr_is_tainted(expr.left) or self._expr_is_tainted(expr.right)
        if isinstance(expr, c_ast.UnaryOp):
            return self._expr_is_tainted(expr.expr)
        # If it's a cast, check the inner expression
        if isinstance(expr, c_ast.Cast):
            return self._expr_is_tainted(expr.expr)
        # If it's an array reference (e.g., arr[i]), treat it like the array ID
        if isinstance(expr, c_ast.ArrayRef):
            # Check array name or index for taint (index taint doesn't taint the data, but array content could be)
            # We simplify: if array variable itself is tainted, mark taint (this is conservative)
            return self._expr_is_tainted(expr.name)
        # Struct reference (field access via . or ->)
        if isinstance(expr, c_ast.StructRef):
            return self._expr_is_tainted(expr.name)
        return False
    
    def _get_tainted_vars_in_expr(self, expr):
        tainted_vars = []
        if isinstance(expr, c_ast.ID):
            if expr.name in self._tainted_vars:
                tainted_vars.append(expr.name)
        elif isinstance(expr, c_ast.BinaryOp):
            tainted_vars += self._get_tainted_vars_in_expr(expr.left)
            tainted_vars += self._get_tainted_vars_in_expr(expr.right)
        elif isinstance(expr, c_ast.UnaryOp):
            tainted_vars += self._get_tainted_vars_in_expr(expr.expr)
        elif isinstance(expr, c_ast.Cast):
            tainted_vars += self._get_tainted_vars_in_expr(expr.expr)
        elif isinstance(expr, c_ast.ArrayRef):
            tainted_vars += self._get_tainted_vars_in_expr(expr.name)
        elif isinstance(expr, c_ast.StructRef):
            tainted_vars += self._get_tainted_vars_in_expr(expr.name)
        elif isinstance(expr, c_ast.FuncCall):
            if isinstance(expr.name, c_ast.ID) and expr.name.name == "getenv":
                tainted_vars.append(f"env({expr.args.exprs[0].value})")  # e.g., env("HOME")
            # Also collect taint from any arguments to this function call
            if expr.args:
                for arg in expr.args.exprs:
                    tainted_vars += self._get_tainted_vars_in_expr(arg)
        return list(set(tainted_vars))
    
    def _make_recommendation(self, func_name):
        # Generic suggestions for different cases
        if func_name == "system" or func_name == "popen" or func_name == "_popen":
            # Suggest using execve or specific API
            return ("Avoid using system/popen. "
                    "If you need to execute external commands, use a safer function like execve() with sanitized arguments, "
                    "or better, perform the task with library calls (e.g., use unlink() to delete a file instead of `system(\"rm ...\")`).")
        elif func_name.startswith("exec"):
            # It's already using exec family
            return ("Avoid calling exec functions with untrusted input. "
                    "Use execve() with a full path and a sanitized environment, or ensure all arguments are validated. "
                    "If possible, refactor to not spawn a new process.")
        else:
            # Fallback generic recommendation
            return ("Avoid spawning new processes from this code. "
                    "Use safer alternatives or sanitize inputs rigorously.")
