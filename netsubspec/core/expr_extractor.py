import re
from typing import List, Union
from netsubspec.utils.error import fatal_error
from netsubspec.utils.regex import CONST_PATTERN
from netsubspec.core.expr_node import *

class ExprExtractor:
    def __init__(self) -> None:
        self.__expr_nodes: ExprList = []

    def parse(self, smt_lines: List[str]) -> None:
        """Parse a list of SMT-LIB lines and extract expression trees."""
        for line in smt_lines:
            line = line.strip()
            if not (line.startswith("(assert") and line.endswith(")")):
                continue

            inner_expr = line[len("(assert"):-1].strip()
            try:
                tokens = self.__tokenize(inner_expr)
                s_expr = self.__parse_sexpr(tokens)
                expr_node = self.__convert_to_expr_node(s_expr)
                self.__expr_nodes.append(self.__simplify_expr(expr_node))
            except Exception as e:
                fatal_error("ExprExtractor.parse()", f"Parsing failed: {e}.")

    def __tokenize(self, expr: str) -> List[str]:
        """Tokenize an SMT-LIB expression string."""
        token_pattern = re.compile(
            r"""\s*(?:
                (?P<open>\() |
                (?P<close>\)) |
                (?P<quoted>\|(?:[^\\|]|\\.)*?\|) |
                (?P<atom>[^\s()]+)
            )""", re.VERBOSE
        )
        return [match.group().strip() for match in token_pattern.finditer(expr)]

    def __parse_sexpr(self, tokens: List[str]) -> Union[str, List]:
        """Parse tokens into an S-expression."""
        if not tokens:
            fatal_error("ExprExtractor.__parse_sexpr()", "Unexpected end of tokens.")

        token = tokens.pop(0)
        if token == "(":
            expr_list = []
            while tokens:
                if tokens[0] == ")":
                    tokens.pop(0)
                    return expr_list
                expr_list.append(self.__parse_sexpr(tokens))
            fatal_error("ExprExtractor.__parse_sexpr()", "Missing closing parenthesis.")
        elif token == ")":
            fatal_error("ExprExtractor.__parse_sexpr()", "Unexpected ')'.")
        else:
            return token

    def __convert_to_expr_node(self, expr: Union[str, List]) -> ExprNode:
        """Convert an S-expression to an ExprNode tree."""
        if isinstance(expr, str):
            if expr in ("true", "false") or CONST_PATTERN.fullmatch(expr):
                return make_const(expr)
            return make_var(expr)

        if not expr:
            fatal_error("ExprExtractor.__convert_to_expr_node()", "Empty expression.")

        op = expr[0]
        args = [self.__convert_to_expr_node(e) for e in expr[1:]]
        return ExprNode(op, args)

    def __simplify_expr(self, expr: ExprNode) -> ExprNode:
        """Simplify the ExprNode recursively, like z3 simplify()."""
        simplified_args = [
            self.__simplify_expr(arg) if isinstance(arg, ExprNode) else arg
            for arg in expr.args
        ]

        if expr.op == "and":
            if any(a.is_const_false() for a in simplified_args):
                return make_const("false")
            args = [a for a in simplified_args if not a.is_const_true()]
            return make_const("true") if not args else (args[0] if len(args) == 1 else ExprNode("and", args))

        elif expr.op == "or":
            if any(a.is_const_true() for a in simplified_args):
                return make_const("true")
            args = [a for a in simplified_args if not a.is_const_false()]
            return make_const("false") if not args else (args[0] if len(args) == 1 else ExprNode("or", args))

        elif expr.op == "ite":
            cond, then_branch, else_branch = simplified_args
            if cond.is_const_true():
                return then_branch
            elif cond.is_const_false():
                return else_branch
            return ExprNode("ite", [cond, then_branch, else_branch])

        elif expr.op == "=>":
            cond, then_branch = simplified_args
            if cond.is_const_true():
                return then_branch
            if cond.is_const_false():
                return make_const("true")
            return ExprNode("=>", [cond, then_branch])

        return ExprNode(expr.op, simplified_args)

    def get_expr_nodes(self) -> ExprList:
        return self.__expr_nodes
