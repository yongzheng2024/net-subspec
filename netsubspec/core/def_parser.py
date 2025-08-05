from typing import Set, Dict
from dataclasses import dataclass

from netsubspec.utils.error import *
from netsubspec.core.expr_node import *

class DefParser:
    def __init__(self, expr_nodes: Dict[ExprNode, bool]) -> None:
        self.__expr_nodes: Dict[ExprNode, bool] = expr_nodes
        # self.__inter_vars: List[ExprNode] = []

        # deduced variable definition -> conditional expressions
        self.__def_to_conds: Dict[ExprNode, Set[ExprNode]] = {}

    def parse(self) -> None:
        """Parse variable definitions from expression nodes excluding select-route."""
        for expr, select_route_flag in self.__expr_nodes.items():
            if select_route_flag:  continue
            self.__parse_expr(expr, None)

    def __parse_expr(self, expr: ExprNode, conds: ExprNode) -> None:
        """Recursively parse expressions to find definition clauses."""
        op = expr.op
        args = expr.args

        if op in {"and", "or"}:
            for sub_expr in args:
                self.__parse_expr(sub_expr, conds)

        elif "ite" == op:
            conds_, then_, else_ = args
            not_conds_ = make_not(conds_)
            then_conds = conds if conds == conds_     else make_and(conds, conds_)
            else_conds = conds if conds == not_conds_ else make_and(conds, not_conds_)
            self.__parse_expr(then_, then_conds)
            self.__parse_expr(else_, else_conds)

        elif "=>" == op:
            conds_, then_ = args
            then_conds = conds if conds == conds_ else make_and(conds, conds_)
            self.__parse_expr(then_, then_conds)

        elif "=" == op and (args[0].is_ite() or args[1].is_ite()):
            if args[0].is_ite() and args[1].is_ite():
                fatal_error("DefParser.__parse_expr()", 
                        "The equality expressions include two ite sub-expressions." +  \
                        f"\n  {expr}")
            sub_expr: ExprNode = None
            ite_expr: ExprNode = None
            if args[0].is_ite():  ite_expr, sub_expr = args
            else:                 sub_expr, ite_expr = args
            conds_, then_, else_ = ite_expr.args
            not_conds_ = make_not(conds_)
            then_conds = conds if conds == conds_     else make_and(conds, conds_)
            else_conds = conds if conds == not_conds_ else make_and(conds, not_conds_)
            then_equal_exprs = make_equal(sub_expr, then_)
            else_equal_exprs = make_equal(sub_expr, else_)
            self.__parse_expr(then_equal_exprs, then_conds)
            self.__parse_expr(else_equal_exprs, else_conds)

        else:
            self.__parse_def(expr, conds)

    """
    def __parse_def(self, expr: ExprNode, defs: Set[ExprNode]) -> None:
        if not expr.is_var():
            fatal_error("DefParser.__parse_def()", f"Invalid ExprNode {expr}.")

        var_name = expr.args[0]
        if "reachable-id" in var_name:
            pass

        elif "history" in var_name:
            pass

        elif "permitted" in var_name:
            pass

        elif "choice" in var_name:
            pass

        elif "CONTROL-FORWARDING" in var_name:
            pass

        elif "DATA-FORWARDING" in var_name:
            pass

        else:
            pass
    """

    def __parse_def(self, expr: ExprNode, conds: ExprNode) -> None:
        op = expr.op
        args = expr.args

        if "=" == op:
            lhs, rhs = args
            if lhs.is_var() and rhs.is_const():
                self.__add_def_to_conds(expr, conds)
            elif lhs.is_const() and rhs.is_var():
                swapped_expr = make_equal(rhs, lhs)
                self.__add_def_to_conds(swapped_expr, conds)
            elif lhs.is_var() and rhs.is_var():
                lhs_var = lhs.args[0]
                rhs_var = rhs.args[0]
                if "prefixLength" in lhs_var and "prefixLength" in rhs_var or  \
                        "adminDist" in lhs_var and "adminDist" in rhs_var or   \
                        "metric" in lhs_var and "metric" in rhs_var or         \
                        "community" in lhs_var and "community" in rhs_var:
                    swapped_expr = make_equal(rhs, lhs)
                    self.__add_def_to_conds(expr, conds)
                    self.__add_def_to_conds(swapped_expr, conds)
            else:
                warn_if_false(False, "DefParser.parse_def()", 
                              f"Unsupported equality expression {expr}.")

        elif ">" == op and args[0].is_reachable_id():
            self.__add_def_to_conds(expr, conds)

        elif "not" == op:
            inner = args[0]
            if inner.is_var():
                expr_equal_false = make_equal(inner, make_const("false"))
                self.__add_def_to_conds(expr_equal_false, conds)

        elif "var" == op:
            expr_equal_true = make_equal(expr, make_const("true"))
            self.__add_def_to_conds(expr_equal_true, conds)

        else:
            warn_if_false(False, "DefParser.parse_def()", 
                          f"Unsupported expression {expr}.")

    def __add_def_to_conds(self, expr: ExprNode, conds: ExprNode) -> None:
        """
        if expr in self.__def_to_conds.keys():
            if conds == self.__def_to_conds[expr]:
                warn_if_false(False, "DefParser.__add_def_to_conds()", 
                              f"Repeated definition about expr {expr}."
                              "\n  {conds}")
            else:
                fatal_error("DefParser.__add_def_to_conds()", 
                            f"Multiple definition about expr {expr}."
                            f"\n  {self.__def_to_conds[expr]}"
                            f"\n  {conds}")
        self.__def_to_conds[expr] = conds
        """
        if expr not in self.__def_to_conds.keys():
            self.__def_to_conds[expr] = set()
        self.__def_to_conds[expr].add(conds)

    def get_def_to_conds(self) -> Dict[ExprNode, Set[ExprNode]]:
        return self.__def_to_conds
