import os

from netsubspec.core.expr_node import ExprNode, ExprList
from netsubspec.core.expr_parser import ExprParser
from netsubspec.core.def_parser import DefParser
from netsubspec.core.expr_simplifier import ExprSimplifier

def run_pipeline(work_dir: str) -> None:
    smt_encoding_file = os.path.join(work_dir, 'sliced_smt_encoding.smt2')

    # Read SMT assert expressions
    with open(smt_encoding_file, 'r', encoding='utf-8') as f:
        smt_encoding = f.read()
        smt_lines = smt_encoding.splitlines()

    # Parse SMT expressions
    expr_parser = ExprParser(smt_encoding, smt_lines)
    expr_parser.compute()
    var_consts = expr_parser.get_var_consts()
    expr_parser.parse()
    expr_nodes = expr_parser.get_expr_nodes()

    # Extract the definitions of variables
    def_parser = DefParser(expr_nodes)
    def_parser.parse()
    var_defs = def_parser.get_var_defs()

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
    """
