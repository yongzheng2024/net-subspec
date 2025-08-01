import re
from typing import List as TList, Union as TUnion, Dict

from netsubspec.utils.error import *
from netsubspec.utils.regex import *
from netsubspec.utils.utils import *
from netsubspec.core.expr_node import *

from z3 import *

class ExprParser:
    def __init__(self, smt_encoding, smt_lines) -> None:
        self.__smt_encoding: str        = smt_encoding
        self.__smt_lines:    TList[str] = smt_lines

        self.__config_var_consts: Dict[ExprNode, ExprNode] = {}
        self.__inter_var_consts:  Dict[ExprNode, ExprNode] = {}
        self.__expr_nodes: ExprList = []

    # FIXME: Improve this method according to the following two approaches.
    #        1. model checking via Promela/SPIN
    #        2. static analysis for computing the fixed point
    def compute(self) -> None:
        """Compute values of intermediate variables via calling Z3."""
        for line in self.__smt_lines:
            line = line.strip()

            if declare_fun_match := DECLARE_FUN_PATTERN.fullmatch(line):
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
                        self.__inter_var_consts[var_exprnode] = const_true_exprnode
                    elif not var_result and var_not_result:
                        self.__inter_var_consts[var_exprnode] = const_false_exprnode
                    else:
                        self.__inter_var_consts[var_exprnode] = None
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

                    var_history_exprnode:   ExprNode = make_var(var_name)
                    const_history_exprnode: ExprNode = make_const(history_true_const)

                    if 1 == history_true_counter:
                        self.__inter_var_consts[var_history_exprnode] = const_history_exprnode
                    else:
                        fatal_error("ExprParser.compute()",  \
                            f"Invalid evaluation about the history variable {var_name}.")

            elif config_const_match := CONFIG_CONST_PATTERN.fullmatch(line):
                config_var_name: str  = ""
                config_var_const: str = ""
                if config_const_match.group("var1"):
                    config_var_name = config_const_match.group("var1")
                    config_var_const = "true"
                elif config_const_match.group("var2"):
                    config_var_name = config_const_match.group("var2")
                    config_var_const = "false"
                else:
                    config_var_name = config_const_match.group("var3")
                    config_var_const = config_const_match.group("const")
                var_config_exprnode:   ExprNode = make_var(config_var_name)
                const_config_exprnode: ExprNode = make_const(config_var_const)
                self.__config_var_consts[var_config_exprnode] = const_config_exprnode

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
                fatal_error("ExprParser.parse()", f"Parsing failed: {e}.")

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
            fatal_error("ExprParser.__parse_sexpr()", "Unexpected end of tokens.")

        token = tokens.pop(0)
        if token == "(":
            expr_list = []
            while tokens:
                if tokens[0] == ")":
                    tokens.pop(0)
                    return expr_list
                expr_list.append(self.__parse_sexpr(tokens))
            fatal_error("ExprParser.__parse_sexpr()", "Missing closing parenthesis.")
        elif token == ")":
            fatal_error("ExprParser.__parse_sexpr()", "Unexpected ')'.")
        else:
            return token

    def __convert_to_expr_node(self, expr: TUnion[str, TList]) -> ExprNode:
        """Convert an S-expression to an ExprNode tree."""
        if isinstance(expr, str):
            if expr in ("true", "false") or CONST_PATTERN.fullmatch(expr):
                return make_const(expr)
            return make_var(expr)

        if not expr:
            fatal_error("ExprParser.__convert_to_expr_node()", "Empty expression.")

        op = expr[0]
        args = [self.__convert_to_expr_node(e) for e in expr[1:]]
        return ExprNode(op, args)

    def __simplify_expr(self, expr: ExprNode) -> ExprNode:
        """Simplify the ExprNode recursively, like z3 simplify()."""
        # Replace variables with deduced constants, recursively.
        replaced_args = [
            self.__replace_var(arg) if isinstance(arg, ExprNode) and arg.is_var() 
            else arg
            for arg in expr.args
        ]

        # Simplify sub-expressions according to the following rules, recursively.
        simplified_args = [
            self.__simplify_expr(arg) if isinstance(arg, ExprNode) 
            else arg 
            for arg in replaced_args
        ]

        # Simplification rules.
        if "and" == expr.op:
            if any(a.is_const_false() for a in simplified_args):
                return make_const("false")
            args = [a for a in simplified_args if not a.is_const_true()]
            return make_const("true") if not args  \
                else (args[0] if len(args) == 1 else ExprNode("and", args))

        elif "or" == expr.op:
            if any(a.is_const_true() for a in simplified_args):
                return make_const("true")
            args = [a for a in simplified_args if not a.is_const_false()]
            return make_const("false") if not args  \
                else (args[0] if len(args) == 1 else ExprNode("or", args))

        elif "ite" == expr.op:
            cond, then_branch, else_branch = simplified_args
            if cond.is_const_true():
                return then_branch
            elif cond.is_const_false():
                return else_branch
            return ExprNode("ite", [cond, then_branch, else_branch])

        elif "=>" == expr.op:
            cond, then_branch = simplified_args
            if cond.is_const_true():
                return then_branch
            if cond.is_const_false():
                return make_const("true")
            return ExprNode("=>", [cond, then_branch])

        elif "=" == expr.op:
            lhs, rhs = simplified_args
            if lhs.is_const() and rhs.is_const():
                if lhs == rhs:  return make_const("true")
                else:           warn_if_false(False, "ExprParser.__simplify_expr()", 
                                              f"Incorrect equality expression {expr}.")

        return ExprNode(expr.op, simplified_args)

    def __replace_var(self, expr: ExprNode) -> ExprNode:
        if not expr.is_var():
            fatal_error("ExprParser.__replace_var()", "Not variable ExprNode.")

        if expr in self.__config_var_consts.keys() and  \
            self.__config_var_consts[expr]:  return self.__config_var_consts[expr]
        elif expr in self.__inter_var_consts.keys() and  \
            self.__inter_var_consts[expr]:   return self.__inter_var_consts[expr]
        
        return expr

    def get_config_var_consts(self) -> Dict[ExprNode, ExprNode]:
        return self.__config_var_consts

    def get_inter_var_consts(self) -> Dict[ExprNode, ExprNode]:
        return self.__inter_var_consts

    def get_var_consts(self) -> Dict[ExprNode, ExprNode]:
        return self.__config_var_consts | self.__inter_var_consts

    def get_expr_nodes(self) -> ExprList:
        return self.__expr_nodes

    def print_var_consts(self, delimiter_flag: bool = False) -> None:
        for var, const in self.__config_var_consts.items():
            print(f"{var}: {const}")
        for var, const in self.__inter_var_consts.items():
            print(f"{var}: {const}")
        if delimiter_flag:
            print("------------------------------------------------------------"
                  "--------------------")

    def print_expr_nodes(self, delimiter_flag: bool = False) -> None:
        for expr in self.__expr_nodes:
            print(f"(assert {expr})")
        if delimiter_flag:
            print("------------------------------------------------------------"
                  "--------------------")
