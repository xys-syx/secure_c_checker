from pycparser import c_ast
from core.rule import Rule

class MSC32C(Rule):
    def __init__(self):
        super().__init__()
        self.id = self.rule_id = "MSC32-C"
        self.name = "Properly seed pseudorandom number generators"
        self._violations = []
        self._rand_funcs = {"rand", "random"}
        self._seed_funcs = {"srand", "srandom"}
        self._severity_map = {
            "UNSEEDED": "HIGH",
            "CONST-SEED": "HIGH",
            "LOW-ENTROPY": "MEDIUM",
            "MEDIUM-ENTROPY": "LOW"
        }
        self.state_rand = 0
        self.state_random = 0

    def analyze(self, code: str, filename: str = "<unknown>", tainted_vars=None):
        return

    def check(self, ast, filename: str = "<unknown>", tainted_vars=None):
        """Run the MSC32-C analysis on the AST of a single C file."""
        self._violations.clear()
        for ext in ast.ext:
            if isinstance(ext, c_ast.FuncDef):
                self.state_rand = 0
                self.state_random = 0
                self._analyze_block(ext.body)
        return self._violations

    def _report(self, coord, category, message):
        severity = self._severity_map.get(category, "LOW")
        location = str(coord) if coord else "<unknown>:?"
        self._violations.append({
            "rule": self.id,
            "category": category,
            "location": location,
            "severity": severity,
            "description": message
        })

    def _merge_flag(self, flag1, flag2):
        if flag1 == flag2:
            return flag1
        return 2

    def _evaluate_constant_expr(self, expr):
        if isinstance(expr, c_ast.Constant):
            if expr.type in ("int", "char"):
                val_str = expr.value
                if expr.type == "char":
                    val_str = str(ord(val_str.strip("'\"")[0])) if len(val_str.strip("'\"")) == 1 else val_str
                try:
                    return int(val_str, 0)
                except ValueError:
                    return None
        elif isinstance(expr, c_ast.BinaryOp):
            left_val = self._evaluate_constant_expr(expr.left)
            right_val = self._evaluate_constant_expr(expr.right)
            if left_val is not None and right_val is not None:
                try:
                    if expr.op == '+': return left_val + right_val
                    if expr.op == '-': return left_val - right_val
                    if expr.op == '*': return left_val * right_val
                    if expr.op == '/': return left_val // right_val if right_val != 0 else None
                    if expr.op == '%': return left_val % right_val if right_val != 0 else None
                    if expr.op == '<<': return left_val << right_val
                    if expr.op == '>>': return left_val >> right_val
                    if expr.op == '^': return left_val ^ right_val
                    if expr.op == '|': return left_val | right_val
                    if expr.op == '&': return left_val & right_val
                except Exception:
                    return None
        elif isinstance(expr, c_ast.UnaryOp):
            val = self._evaluate_constant_expr(expr.expr)
            if val is not None:
                return +val if expr.op == '+' else -val if expr.op == '-' else None
        elif isinstance(expr, c_ast.Cast):
            return self._evaluate_constant_expr(expr.expr)
        return None

    def _classify_seed_expr(self, expr):
        has_const = False
        has_time = False
        has_pid = False

        def traverse(node):
            nonlocal has_const, has_time, has_pid
            if node is None:
                return
            if isinstance(node, c_ast.Constant):
                if node.type in ("int", "char"):
                    has_const = True
            elif isinstance(node, c_ast.FuncCall):
                if isinstance(node.name, c_ast.ID):
                    name = node.name.name
                    if name == "time":
                        has_time = True
                    elif name == "getpid":
                        has_pid = True
                if node.args:
                    for arg in node.args.exprs:
                        traverse(arg)
            elif isinstance(node, c_ast.ID):
                return
            elif isinstance(node, c_ast.BinaryOp):
                traverse(node.left)
                traverse(node.right)
            elif isinstance(node, c_ast.UnaryOp):
                traverse(node.expr)
            elif isinstance(node, c_ast.Cast):
                traverse(node.expr)
            elif isinstance(node, c_ast.ExprList):
                for child in node.exprs:
                    traverse(child)
            else:
                for _, child in node.children():
                    traverse(child)

        traverse(expr)
        if has_const and not (has_time or has_pid):
            val = self._evaluate_constant_expr(expr)
            return "CONST-SEED" if val is not None else "CONST-SEED"
        if has_time and has_pid:
            return "MEDIUM-ENTROPY"
        if has_time or has_pid:
            return "LOW-ENTROPY"
        return None

    def _analyze_block(self, compound):
        if compound is None or not isinstance(compound, c_ast.Compound) or compound.block_items is None:
            return False
        for stmt in compound.block_items:
            if self._analyze_statement(stmt) == "return":
                return True
        return False

    def _analyze_statement(self, node):
        if isinstance(node, c_ast.Compound):
            if self._analyze_block(node):
                return "return"
        elif isinstance(node, c_ast.Return):
            if node.expr:
                self._analyze_expression(node.expr)
            return "return"
        elif isinstance(node, c_ast.If):
            prev_rand, prev_random = self.state_rand, self.state_random
            if node.cond:
                self._analyze_expression(node.cond)
            cond_state_rand, cond_state_random = self.state_rand, self.state_random

            self.state_rand, self.state_random = cond_state_rand, cond_state_random
            returned_then = False
            if node.iftrue:
                returned_then = self._analyze_block(node.iftrue) if isinstance(node.iftrue, c_ast.Compound) \
                                else (self._analyze_statement(node.iftrue) == "return")
            state_then_rand, state_then_random = self.state_rand, self.state_random

            self.state_rand, self.state_random = cond_state_rand, cond_state_random
            returned_else = False
            if node.iffalse:
                returned_else = self._analyze_block(node.iffalse) if isinstance(node.iffalse, c_ast.Compound) \
                                else (self._analyze_statement(node.iffalse) == "return")
            state_else_rand, state_else_random = self.state_rand, self.state_random

            if returned_then and returned_else:
                return "return"
            elif returned_then and not returned_else:
                self.state_rand, self.state_random = state_else_rand, state_else_random
            elif returned_else and not returned_then:
                self.state_rand, self.state_random = state_then_rand, state_then_random
            else:
                self.state_rand = self._merge_flag(state_then_rand, state_else_rand)
                self.state_random = self._merge_flag(state_then_random, state_else_random)
        elif isinstance(node, c_ast.For) or isinstance(node, c_ast.While) or isinstance(node, c_ast.DoWhile):
            entry_rand, entry_random = self.state_rand, self.state_random
            if isinstance(node, c_ast.For):
                if node.init:
                    if isinstance(node.init, c_ast.ExprList):
                        for expr in node.init.exprs:
                            self._analyze_expression(expr)
                    else:
                        self._analyze_statement(node.init)
                if node.cond:
                    self._analyze_expression(node.cond)
            elif isinstance(node, c_ast.While) or isinstance(node, c_ast.DoWhile):
                if node.cond:
                    self._analyze_expression(node.cond)
            self.state_rand, self.state_random = entry_rand, entry_random
            returned_in_loop = False
            if isinstance(node, c_ast.DoWhile):
                if node.stmt:
                    returned_in_loop = self._analyze_block(node.stmt) if isinstance(node.stmt, c_ast.Compound) \
                                       else (self._analyze_statement(node.stmt) == "return")
                if node.cond:
                    self._analyze_expression(node.cond)
            else:
                if node.stmt:
                    returned_in_loop = self._analyze_block(node.stmt) if isinstance(node.stmt, c_ast.Compound) \
                                       else (self._analyze_statement(node.stmt) == "return")
                if isinstance(node, c_ast.For) and node.next:
                    if isinstance(node.next, c_ast.ExprList):
                        for expr in node.next.exprs:
                            self._analyze_expression(expr)
                    else:
                        self._analyze_expression(node.next)

            iter_state_rand, iter_state_random = self.state_rand, self.state_random
            if isinstance(node, c_ast.DoWhile):
                if returned_in_loop:
                    return "return"
                self.state_rand, self.state_random = iter_state_rand, iter_state_random
            else:
                if returned_in_loop:
                    self.state_rand, self.state_random = entry_rand, entry_random
                else:
                    self.state_rand = self._merge_flag(entry_rand, iter_state_rand)
                    self.state_random = self._merge_flag(entry_random, iter_state_random)
        elif isinstance(node, c_ast.FuncCall):
            if node.args:
                for arg in node.args.exprs:
                    self._analyze_expression(arg)
            func_name = node.name.name if isinstance(node.name, c_ast.ID) else None
            if func_name in self._seed_funcs:
                category = None
                if node.args and len(node.args.exprs) > 0:
                    category = self._classify_seed_expr(node.args.exprs[0])
                if category == "CONST-SEED":
                    self._report(node.coord, "CONST-SEED", f"Using a fixed constant seed in {func_name}()")
                elif category == "LOW-ENTROPY":
                    self._report(node.coord, "LOW-ENTROPY", f"Seeding PRNG with low entropy source in {func_name}() (e.g., time)")
                elif category == "MEDIUM-ENTROPY":
                    self._report(node.coord, "MEDIUM-ENTROPY", f"Seeding PRNG with medium entropy sources in {func_name}() (e.g., time ^ pid)")
                if func_name == "srand":
                    self.state_rand = 1
                elif func_name == "srandom":
                    self.state_random = 1
            elif func_name in self._rand_funcs:
                if (func_name == "rand" and self.state_rand != 1) or (func_name == "random" and self.state_random != 1):
                    self._report(node.coord, "UNSEEDED",
                                 f"Use of {func_name}() before pseudo-random generator is properly seeded")

        elif isinstance(node, c_ast.Decl):
            if node.init:
                self._analyze_expression(node.init)
        elif isinstance(node, c_ast.Switch):
            if node.cond:
                self._analyze_expression(node.cond)
            if node.stmt:
                self._analyze_block(node.stmt)
        else:
            if hasattr(node, 'expr'):
                self._analyze_expression(node.expr)
        return None

    def _analyze_expression(self, expr):
        if expr is None:
            return
        if isinstance(expr, c_ast.FuncCall):
            func_name = expr.name.name if isinstance(expr.name, c_ast.ID) else None

            if expr.args:
                for arg in expr.args.exprs:
                    self._analyze_expression(arg)
            if func_name in self._seed_funcs:
                category = None
                if expr.args and len(expr.args.exprs) > 0:
                    category = self._classify_seed_expr(expr.args.exprs[0])
                if category == "CONST-SEED":
                    self._report(expr.coord, "CONST-SEED", f"Using a fixed constant seed in {func_name}()")
                elif category == "LOW-ENTROPY":
                    self._report(expr.coord, "LOW-ENTROPY", f"Seeding PRNG with low entropy source in {func_name}()")
                elif category == "MEDIUM-ENTROPY":
                    self._report(expr.coord, "MEDIUM-ENTROPY", f"Seeding PRNG with medium entropy sources in {func_name}()")

                if func_name == "srand":
                    self.state_rand = 1
                elif func_name == "srandom":
                    self.state_random = 1
            elif func_name in self._rand_funcs:
                if (func_name == "rand" and self.state_rand != 1) or (func_name == "random" and self.state_random != 1):
                    self._report(expr.coord, "UNSEEDED",
                                 f"Use of {func_name}() before PRNG is properly seeded")

        elif isinstance(expr, c_ast.BinaryOp):
            self._analyze_expression(expr.left)
            self._analyze_expression(expr.right)
        elif isinstance(expr, c_ast.UnaryOp):
            self._analyze_expression(expr.expr)
        elif isinstance(expr, c_ast.Cast):
            self._analyze_expression(expr.expr)
        elif isinstance(expr, c_ast.ArrayRef):
            self._analyze_expression(expr.subscript)
        elif isinstance(expr, c_ast.TernaryOp):
            self._analyze_expression(expr.cond)
            self._analyze_expression(expr.iftrue)
            self._analyze_expression(expr.iffalse)
