import os
from netsubspec.core.expr_node import ExprNode, ExprList
from netsubspec.core.expr_extractor import ExprExtractor
from netsubspec.core.def_extractor import DefParser
from netsubspec.core.expr_simplifier import ExprSimplifier

def run_pipeline(work_dir: str) -> ExprList:
    smt_encoding_file = os.path.join(work_dir, 'inlined_smt_encoding.smt2')

    # Read SMT assert expressions
    with open(smt_encoding_file, 'r', encoding='utf-8') as f:
        smt_lines = f.read().splitlines()

    # Parse SMT expressions
    expr_extractor = ExprExtractor()
    expr_extractor.parse(smt_lines)
    expr_nodes = expr_extractor.get_expr_nodes()

    """
    # Extract variables' definition
    def_parser = DefParser(expr_nodes)
    def_parser.parse()
    var_defs = def_parser.get_var_defs()

    print()
    print()
    print()
    for var, clauses in var_defs.items():
        print(f"Variable {var} defined in:")
        for clause in clauses:
            print("  ", clause)
        print("-----------------------------------------------------------------")
    """

    # Simplify expressions
    expr_simplifier = ExprSimplifier(expr_nodes)
    expr_simplifier.replace_all()
    simplified_nodes = expr_simplifier.get_expr_nodes()
    best_routes = expr_simplifier.get_best_routes()

    for var, clauses in best_routes.items():
        print(f"Variable {var} defined in:")
        for clause in clauses:
            print("  ", clause)
        print("-----------------------------------------------------------------")
