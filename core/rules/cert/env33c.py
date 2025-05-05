from core.rule import Rule
from pycparser import c_parser, c_ast
from pycparser.c_ast import NodeVisitor, ID, Constant

class ENV33C(Rule, NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "ENV33-C"
        #self._violations = []
        self.name = "Do not call system() or equivalent"
        # self.description = ("Detects usage of dangerous process-spawning functions "
        #                     "like system(), popen(), execlp(), execvp(), etc., as per CERT ENV33-C")
        self._dangerous_funcs = {"system", "popen", "_popen", "_wpopen", "execlp", "execvp"}
        self._tainted_vars = set()
        self._tainted_sources = set()
        self._var_sources = {}
        self.descriptions = {
            "system": "system() command execution",
            "popen": "popen() command execution with a pipe",
            "_popen": "_popen() command execution with a pipe",
            "_wpopen": "_wpopen() command execution with a pipe (wide-char)",
            "execvp": "execvp() execution of program via PATH search",
            "execlp": "execlp() execution of program via PATH search"
        }
        self.severity_levels = {
            fname: "LOW"
            for fname in self._dangerous_funcs
        }
    
    def analyze(self, code: str, filename: str = "<unknown>"):
        # if ast is None:
        #     return []
        # self.current_file = filename
        # self.visit(ast)
        # return self._violations
        return
    
    def check(self, ast, filename: str = "<unknown>", tainted_vars=None):
        self._violations.clear()
        self._tainted_vars = set(tainted_vars) if tainted_vars else set()
        self._tainted_sources = set()
        self._var_sources = {}
        self.filename = filename
        self.visit(ast)
        return self._violations

    def visit_FuncDef(self, node):
        prev_tainted_vars = self._tainted_vars
        prev_tainted_sources = self._tainted_sources
        prev_var_sources = self._var_sources
        self._tainted_vars = set()
        self._tainted_sources = set()
        self._var_sources = {}
        # Mark all function parameters as tainted
        if node.decl.type.args:
            for param in node.decl.type.args.params:
                if isinstance(param, c_ast.Decl) and param.name:
                    self._tainted_vars.add(param.name)
                    self._tainted_sources.add(param.name)
        self.visit(node.body)
        self._tainted_vars = prev_tainted_vars
        self._tainted_sources = prev_tainted_sources
        self._var_sources = prev_var_sources

    def visit_Assignment(self, node):
        self.generic_visit(node)
        if node.op == '=':
            if isinstance(node.lvalue, ID):
                target_var = node.lvalue.name
                if self._expr_is_tainted(node.rvalue):
                    self._tainted_vars.add(target_var)
                    taint_names = self._get_tainted_vars_in_expr(node.rvalue)
                    sources = []
                    for name in set(taint_names):
                        if name in self._tainted_sources or name.startswith("env("):
                            sources.append(name)
                        elif name in self._var_sources:
                            sources.extend(self._var_sources[name])
                    sources = list(set(sources))
                    self._var_sources[target_var] = sources

    def visit_Decl(self, node):
        self.generic_visit(node)
        if node.init is not None:
            var_name = node.name
            if self._expr_is_tainted(node.init):
                self._tainted_vars.add(var_name)
                taint_names = self._get_tainted_vars_in_expr(node.init)
                sources = []
                for name in set(taint_names):
                    if name in self._tainted_sources or name.startswith("env("):
                        sources.append(name)
                    elif name in self._var_sources:
                        sources.extend(self._var_sources[name])
                self._var_sources[var_name] = sources
            # if isinstance(node.type, c_ast.TypeDecl):
            #     var_name = node.name
            #     if self._expr_is_tainted(node.init):
            #         self._tainted_vars.add(var_name)
            #         taint_names = self._get_tainted_vars_in_expr(node.init)
            #         sources = []
            #         for name in set(taint_names):
            #             if name in self._tainted_sources or name.startswith("env("):
            #                 sources.append(name)
            #             elif name in self._var_sources:
            #                 sources.extend(self._var_sources[name])
            #         sources = list(set(sources))
            #         self._var_sources[var_name] = sources


    def is_tainted_expr(self, expr):
        if expr is None:
            return False
        if isinstance(expr, ID):
            return expr.name in self._tainted_vars
        if isinstance(expr, c_ast.ArrayRef):
            if isinstance(expr.name, ID) and expr.name.name == "argv":
                return True
        if isinstance(expr, c_ast.FuncCall):
            if isinstance(expr.name, ID) and expr.name.name == "getenv":
                return True
            
        for child_name, child in expr.children():
            if self.is_tainted_expr(child):
                return True
            
        return False
    
    def visit_FuncCall(self, node):
        func_name = None
        if isinstance(node.name, ID):
            func_name = node.name.name
        # elif isinstance(node.name, c_ast.FuncCall):
        #     func_name = None
        if func_name and func_name in self._dangerous_funcs:
            args = node.args.exprs if node.args else []
            if func_name == "system" and args:
                if func_name == "system" and args:
                    if self._is_null_pointer(args[0]):
                        return
            
            tainted_found = False
            all_const = True
            tainted_names = []
            for expr in args:
                if self._expr_is_tainted(expr):
                    tainted_found = True
                    tainted_names.extend(self._get_tainted_vars_in_expr(expr))
                if not self._expr_is_constant(expr):
                    all_const = False
            severity = "LOW"
            if tainted_found:
                severity = "HIGH"
            elif not all_const:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            path_search = False
            relative_path = False
            if args:
                first_arg = args[0]
                if self._is_const_string(first_arg):
                    cmd_str = first_arg.value.strip('"')
                    if func_name in {"execlp", "execvp"} and cmd_str.startswith("/"):
                        return
                    if '/' in cmd_str:
                        if not cmd_str.startswith("/"):
                            relative_path = True
                    else:
                        path_search = True
                else:
                    if func_name in {"execlp", "execvp"}:
                        if severity == "LOW":
                            severity = "MEDIUM"
                if not tainted_found:
                    if (path_search or relative_path) and severity == "LOW":
                        severity = "MEDIUM"
                description = f"Unsafe call to {func_name}()"
                if tainted_found:
                    description += " [TAINTED-INPUT]"
                else:
                    if path_search:
                        description += "[PATH-SEARCH]"
                    elif relative_path:
                        description += " [RELATIVE-PATH]"
                tainted_source_list = []
                tainted_vars_list = []
                for name in set(tainted_names):
                    if name in self._tainted_sources or name.startswith("env("):
                        tainted_source_list.append(name)
                    else:
                        tainted_vars_list.append(name)
                        if name in self._var_sources:
                            for src in self._var_sources[name]:
                                tainted_source_list.append(src)
                tainted_source_list = sorted(set(tainted_source_list))
                tainted_vars_list = sorted(set(tainted_vars_list))

                call_var_sources = {
                    var: self._var_sources.get(var, [])
                    for var in tainted_vars_list
                }

                recommendation = self._make_recommendation(func_name)
                self._violations.append({
                    "file": self.filename,
                    "line": node.coord.line,
                    "rule": self.rule_id,
                    "severity": severity,
                    "tainted_sources": tainted_source_list,
                    "tainted_vars": tainted_vars_list,
                    "var_sources": call_var_sources,
                    "description": description,
                    "recommendation": recommendation
                })
                self.generic_visit(node)

    def _is_null_pointer(self, expr):
        return (isinstance(expr, Constant) and expr.type in ('int','char') and expr.value == '0') \
               or (isinstance(expr, ID) and expr.name == "NULL") \
               or (isinstance(expr, c_ast.Cast) and self._is_null_pointer(expr.expr))
    
    def _expr_is_constant(self, expr):
        return isinstance(expr, Constant)
    
    def _is_const_string(self, expr):
        return isinstance(expr, Constant) and expr.type == 'string'
    
    def _expr_is_tainted(self, expr):
        if isinstance(expr, ID):
            return expr.name in self._tainted_vars
        if isinstance(expr, Constant):
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
        if isinstance(expr, c_ast.Cast):
            return self._expr_is_tainted(expr.expr)
        if isinstance(expr, c_ast.ArrayRef):
            return self._expr_is_tainted(expr.name)
        if isinstance(expr, c_ast.StructRef):
            return self._expr_is_tainted(expr.name)
        return False
    
    def _get_tainted_vars_in_expr(self, expr):
        tainted_vars = []
        if isinstance(expr, ID) and expr.name in self._tainted_vars:
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
            if isinstance(expr.name, ID) and expr.name.name == "getenv":
                #tainted_vars.append(f"env({expr.args.exprs[0].value})")
                if expr.args and expr.args.exprs:
                    arg0 = expr.args.exprs[0]
                    if isinstance(arg0, Constant):
                        tainted_vars.append(f'env({arg0.value.strip("\"")})')
                    else:
                        tainted_vars.append("env(<unknown>)")
            if expr.args:
                for arg in expr.args.exprs:
                    tainted_vars += self._get_tainted_vars_in_expr(arg)
        return tainted_vars
    
    def _make_recommendation(self, func_name):
        if func_name == "system" or func_name == "popen" or func_name == "_popen" or func_name == "_wpopen":
            return ("Avoid using system/popen. "
                    "If you need to execute external commands, use a safer function like execve() with sanitized arguments, "
                    "or better, perform the task with library calls (e.g., use unlink() to delete a file instead of `system(\"rm ...\")`).")
        elif func_name.startswith("exec"):
            return ("Avoid calling exec functions with untrusted input. "
                    "Use execve() with a full path and a sanitized environment, or ensure all arguments are validated. "
                    "If possible, refactor to not spawn a new process.")
        else:
            return ("Avoid spawning new processes from this code. "
                    "Use safer alternatives or sanitize inputs rigorously.")