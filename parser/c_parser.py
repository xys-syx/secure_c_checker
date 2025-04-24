from pycparser import c_parser

class CParser:
    def __init__(self):
        self.parser = c_parser.CParser()

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
