from typing import Set, Dict
from dataclasses import dataclass

from netsubspec.utils.error import *
from netsubspec.core.expr_node import *

class DefParser:
    def __init__(self, expr_nodes: ExprList) -> None:
        self.__expr_nodes: ExprList                 = expr_nodes
        # self.__var_consts: Dict[ExprNode, ExprNode] = var_consts

        # var -> clauses where it is defined
        self.__var_defs: Dict[ExprNode, Set[ExprNode]] = {}

    def parse(self) -> None:
        """Parse variable definitions from expression nodes."""
        for node in self.__expr_nodes:
            self.__parse_expr(node, node)

        """
        for var, defs in self.__var_defs.items():
            self.__parse_def(var, defs)
        """

    def __parse_expr(self, expr_node: ExprNode, original_node: ExprNode) -> None:
        """Recursively parse expressions to find definition clauses."""
        op = expr_node.op
        args = expr_node.args

        if op in {"and", "or"}:
            for sub_expr in args:
                self.__parse_expr(sub_expr, original_node)
        elif op == "ite":
            _, then_expr, else_expr = args
            self.__parse_expr(then_expr, original_node)
            self.__parse_expr(else_expr, original_node)
        elif op == "=>":
            _, then_expr = args
            self.__parse_expr(then_expr, original_node)
        else:
            self.__extract_def(expr_node, original_node)

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

    def __extract_def(self, expr_node: ExprNode, original_node: ExprNode) -> None:
        op = expr_node.op
        args = expr_node.args

        if op == "=":
            lhs, rhs = args
            # If lhs is var, treat lhs as defined
            if lhs.is_var():
                self.__add_var_def(lhs, original_node)
            # If lhs is const and rhs is var, treat rhs as defined
            elif lhs.is_const() and rhs.is_var():
                self.__add_var_def(rhs, original_node)
            else:
                warn_if_false(False, "DefParser.extract_def()", 
                              f"Unsupported equality expression {expr_node}.")

        elif op == ">" and args[0].is_reachable_id():
            self.__add_var_def(args[0], original_node)

        elif op == "not":
            inner = args[0]
            if isinstance(inner, ExprNode) and inner.is_var():
                self.__add_var_def(inner, original_node)

        elif op == "var":
            self.__add_var_def(expr_node, original_node)

        # else: do nothing — no new definitions
        else:
            warn_if_false(False, "DefParser.extract_def()", 
                          f"Unsupported equality expression {expr_node}.")

    def __add_var_def(self, var: ExprNode, clause: ExprNode) -> None:
        if var not in self.__var_defs:
            self.__var_defs[var] = set()
        self.__var_defs[var].add(clause)

    def get_var_defs(self) -> Dict[ExprNode, Set[ExprNode]]:
        return self.__var_defs
