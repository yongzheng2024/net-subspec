import re
from typing import List as TList, Union as TUnion, Dict

from netsubspec.utils.error import warn_if_false, fatal_error
from netsubspec.utils.regex import CONST_PATTERN, DECLARE_FUN_PATTERN
from netsubspec.utils.utils import smt_bin
from netsubspec.core.expr_node import *

from z3 import *

class ExprParser:
    def __init__(self, smt_encoding, smt_lines) -> None:
        self.__smt_encoding: str        = smt_encoding
        self.__smt_lines:    TList[str] = smt_lines

        self.__var_consts: Dict[ExprNode, ExprNode] = {}
        self.__expr_nodes: ExprList = []

    def compute(self) -> None:
        """Compute the value of intermediate variables via calling Z3."""
        for line in self.__smt_lines:
            line = line.strip()
            if not (line.startswith("(declare-fun") and line.endswith(")")):
                continue

            declare_fun_match = DECLARE_FUN_PATTERN.fullmatch(line)
            if not declare_fun_match:
                continue
            var_name: str  = declare_fun_match.group("var")
            type_name: str = declare_fun_match.group("type")

            if "permitted" in var_name or  \
                    "CONTROL-FORWARDING" in var_name or  \
                    "DATA-FORWARDING" in var_name:
                if "Bool" not in type_name:
                    fatal_error("ExprParser.compute()", "Unmatch variable type.")

                var_const     = f"(assert {var_name})"
                var_not_const = f"(assert (not {var_name}))"

                var_result     = self.__check_sat(self.__smt_encoding + var_const)
                var_not_result = self.__check_sat(self.__smt_encoding + var_not_const)

                var_exprnode:         ExprNode = make_var(var_name)
                const_true_exprnode:  ExprNode = make_const("true")
                const_false_exprnode: ExprNode = make_const("false")

                if var_result and not var_not_result:
                    self.__var_consts[var_exprnode] = const_true_exprnode
                elif not var_result and var_not_result:
                    self.__var_consts[var_exprnode] = const_false_exprnode
                else:
                    self.__var_consts[var_exprnode] = None
                    warn_if_false(False, "ExprParser.compute()",  \
                        f"Invalid evaluation about the variable {var_name}.")

            elif "history" in var_name:
                if "BitVec" not in type_name:
                    fatal_error("ExprParser.compute()", "Unmatch variable type.")

                bits = re.search(r"\d+", type_name).group(0)
                const = 0
                maximum = (1 << int(bits)) - 1

                history_true_const = None
                history_true_counter = 0

                while const <= maximum:
                    binary_str = smt_bin(const, int(bits))
                    const += 1
                    var_history_const = f"(assert (= {var_name} {binary_str}))"
                    var_history_result =  \
                        self.__check_sat(self.__smt_encoding + var_history_const)
                    if not var_history_result:
                        continue
                    history_true_const = binary_str
                    history_true_counter += 1

                var_exprnode:           ExprNode = make_var(var_name)
                const_history_exprnode: ExprNode = make_const(history_true_const)

                if 1 == history_true_counter:
                    self.__var_consts[var_exprnode] = const_history_exprnode
                else:
                    fatal_error("ExprParser.compute()",  \
                        f"Invalid evaluation about the history variable {var_name}.")

    def parse(self) -> None:
        """Parse a list of SMT-LIB lines and extract expression trees."""
        for line in self.__smt_lines:
            line = line.strip()
            if not (line.startswith("(assert") and line.endswith(")")):
                continue

            inner_expr = line[len("(assert"):-len(")")].strip()
            try:
                tokens = self.__tokenize(inner_expr)
                s_expr = self.__parse_sexpr(tokens)
                expr_node = self.__convert_to_expr_node(s_expr)
                self.__expr_nodes.append(self.__simplify_expr(expr_node))
            except Exception as e:
                fatal_error("ExprExtractor.parse()", f"Parsing failed: {e}.")

    def __check_sat(self, smt_encoding: str) -> bool:
        """Call z3 to check this smt encoding is SAT or UNSAT, where SAT return True."""
        exprs = parse_smt2_string(smt_encoding)
        s = Solver()
        s.add(exprs)
        result = s.check()
        if sat == result:  return True
        else:              return False

    def __tokenize(self, expr: str) -> TList[str]:
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

    def __parse_sexpr(self, tokens: TList[str]) -> TUnion[str, TList]:
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

    def __convert_to_expr_node(self, expr: TUnion[str, TList]) -> ExprNode:
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

    def get_var_consts(self) -> Dict[ExprNode, ExprNode]:
        return self.__var_consts

    def get_expr_nodes(self) -> ExprList:
        return self.__expr_nodes
