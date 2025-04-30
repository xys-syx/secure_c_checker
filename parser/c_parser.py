from pycparser import c_parser

class CParser:
    def __init__(self):
        self.parser = c_parser.CParser()

    def _strip_directives(self, text: str) -> str:
        return "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith('#')
        )
        
    def parse_text(self, code:str):
        try:
            clean = self._strip_directives(code)
            return self.parser.parse(clean)
        except Exception as exc:
            print(f"[CParser] parse_text() failed: {exc}")
            return None
    
    
    def parse_file(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                code = f.read()

            code = "\n".join([line for line in code.splitlines() if not line.strip().startswith("#")])
            ast = self.parser.parse(code)
            return ast
        except Exception as e:
            print(f"Parsing C File Errors: {e}")
            return None
