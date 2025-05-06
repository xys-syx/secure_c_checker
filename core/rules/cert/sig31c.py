import re
from pycparser import c_ast
from core.rule import Rule
class SIG31C(Rule, c_ast.NodeVisitor):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "SIG31-C"
        self.name = "Do not access shared objects in signal handlers"
        self._violations = []
        self._handler_funcs = set()
        self._global_vars = set()
        self._atomic_types = {"sig_atomic_t"}

    def visit_Decl(self, node):
        if isinstance(node.type, c_ast.TypeDecl):
            if getattr(node, 'func_decl', False) is False:
                self._global_vars.add(node.name)
        self.generic_visit(node)

    def visit_FuncCall(self, node):
        if isinstance(node.name, c_ast.ID) and node.name.name in {"signal", "sigaction"}:
            if node.args and len(node.args.exprs) >= 2:
                handler = node.args.exprs[1]
                if isinstance(handler, c_ast.ID):
                    self._handler_funcs.add(handler.name)
        self.generic_visit(node)

    def visit_FuncDef(self, node):
        func_name = node.decl.name
        if func_name in self._handler_funcs:
            for subnode in node.body.block_items or []:
                ids = []
                subnode.visit(NodeCollector(c_ast.ID, ids))
                for identifier in ids:
                    var_name = identifier.name
                    if var_name in self._global_vars:
                        self._violations.append({
                            "rule": self.id,
                            "message": f"Access to shared variable '{var_name}' in signal handler '{func_name}' (line {identifier.coord.line})"
                        })
        self.generic_visit(node)

class NodeCollector(c_ast.NodeVisitor):
    def __init__(self, node_type, collection):
        self.node_type = node_type
        self.collection = collection
    def visit(self, node):
        if isinstance(node, self.node_type):
            self.collection.append(node)
        # continue traversal
        for _, child in node.children():
            self.visit(child)
