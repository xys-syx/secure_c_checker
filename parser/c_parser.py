from pycparser import c_parser, c_ast
from parser.taint_analyzer import TaintAnalyzer

last_parser = None

class CParser:
    def __init__(self):
        self.parser = c_parser.CParser()
        self.tainted_vars = set()
        self.checker = None

    def _strip_directives(self, text: str) -> str:
        return "\n".join(line for line in text.splitlines()
                         if not line.lstrip().startswith('#'))
    
    def parse_text(self, code: str):
        try:
            clean = self._strip_directives(code)
            ast = self.parser.parse(clean)
            if ast is not None:
                analyzer = TaintAnalyzer()
                analyzer.visit(ast)
                self.tainted_vars = analyzer._taint_vars
            global last_parser
            last_parser = self
            return ast
        except Exception as exc:
            print(f"[CParser] parse_text() failed: {exc}")
            return None
        
    def parse_file(self, filename: str):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                code = f.read()
            code = self._strip_directives(code)
            ast = self.parser.parse(code)
            if ast is not None:
                analyzer = TaintAnalyzer()
                analyzer.visit(ast)
                self.tainted_vars = analyzer._taint_vars
            global last_parser
            last_parser = self
            return ast
        except Exception as e:
            print(f"Parsing C File Error: {e}")
            return None
        
    def get_tainted_vars(self):
        return self.checker._taint_vars if self.checker else set()