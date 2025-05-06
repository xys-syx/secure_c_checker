from core.rule import Rule
from pycparser import c_parser, c_ast
class CON34C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "CON34-C"
        self.name = "Declare shared objects with appropriate storage duration"
        # Track local (automatic) variables in current function
        self._in_func = False
        self._locals = {}  # name -> is_static (True/False)
    
    def check(self, ast, filename="<unknown>", tainted_vars=None):
        self._violations = []
        self.visit(ast)
        return self._violations
    
    def visit_FuncDef(self, node):
        # Enter function: reset local tracking
        prev_in_func = self._in_func
        prev_locals = dict(self._locals)
        self._in_func = True
        self._locals.clear()
        # Mark parameters as local (automatic storage, cannot be static)
        if node.decl.type.args:
            for param in node.decl.type.args.params:
                if isinstance(param, c_ast.Decl) and param.name:
                    self._locals[param.name] = False
        # Visit declarations in function body to record local variables
        for item in (node.body.block_items or []):
            if isinstance(item, c_ast.Decl) and item.name:
                is_static = bool(item.storage) and "static" in item.storage
                self._locals[item.name] = is_static
        # Traverse into function body
        self.generic_visit(node.body)
        # Exit function: restore previous context
        self._in_func = prev_in_func
        self._locals = prev_locals
    
    def visit_FuncCall(self, node):
        # Identify thread creation function calls
        func_name = node.name.name if isinstance(node.name, c_ast.ID) else None
        if func_name in ("pthread_create", "thrd_create"):
            # Determine index of the 'arg' parameter for each function
            arg_index = 3 if func_name == "pthread_create" else 2
            if node.args and len(node.args.exprs) > arg_index:
                arg_expr = node.args.exprs[arg_index]
                # Check if argument is address-of a local variable (UnaryOp('&', ID))
                if isinstance(arg_expr, c_ast.UnaryOp) and arg_expr.op == '&':
                    target = arg_expr.expr
                    if isinstance(target, c_ast.ID):
                        var_name = target.name
                        # If target is a non-static local variable, flag it
                        if var_name in self._locals and self._locals[var_name] is False:
                            self._report(node, "MEDIUM", ["STACK-ADDR"],
                                         f"Passing address of local variable '{var_name}' to new thread")
                    elif isinstance(target, c_ast.ArrayRef):
                        # e.g., &local_array[index]
                        if isinstance(target.name, c_ast.ID):
                            var_name = target.name.name
                            if var_name in self._locals and self._locals[var_name] is False:
                                self._report(node, "MEDIUM", ["STACK-ADDR"],
                                             f"Passing address of element of local array '{var_name}' to new thread")
                    elif isinstance(target, c_ast.StructRef) and target.type == '.':
                        # e.g., &local_struct.field
                        if isinstance(target.name, c_ast.ID):
                            var_name = target.name.name
                            if var_name in self._locals and self._locals[var_name] is False:
                                self._report(node, "MEDIUM", ["STACK-ADDR"],
                                             f"Passing address of field of local struct '{var_name}' to new thread")
                # Check if argument is a direct ID of a local array (decayed pointer to stack memory)
                elif isinstance(arg_expr, c_ast.ID):
                    var_name = arg_expr.name
                    if var_name in self._locals and self._locals[var_name] is False:
                        # If the thread function expects void*, an array name will decay to pointer
                        # Flag using local array by value as well
                        self._report(node, "MEDIUM", ["STACK-ADDR"],
                                     f"Passing local array '{var_name}' (stack memory) to new thread")
        # Continue traversal
        self.generic_visit(node)
    
    def _report(self, node, severity, labels, message):
        self._violations.append({
            "rule": "CON34-C",
            "function": node.name.name if isinstance(node.name, c_ast.ID) else None,
            "location": str(node.coord),
            "severity": severity,
            "description": f"[{labels[0]}] {message}",
            "labels": labels
        })
