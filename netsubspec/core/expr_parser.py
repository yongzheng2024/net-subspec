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

        self.__config_var_to_consts:  Dict[ExprNode, ExprNode] = {}
        self.__inter_var_to_consts:   Dict[ExprNode, ExprNode] = {}
        self.__deduced_var_to_consts: Dict[ExprNode, ExprNode] = {}
        self.__temp_var_to_consts:    Dict[ExprNode, ExprNode] = {}

        # ExprNode -> True if it's a select-route ExprNode, False otherwise.
        self.__expr_nodes: Dict[ExprNode, bool] = {}

    # FIXME: Improve this method according to one of the following approaches.
    #        1. model checking via Promela/SPIN
    #        2. static analysis for computing the fixed point
    def compute(self) -> None:
        """Compute values of intermediate variables via calling Z3."""
        for line in self.__smt_lines:
            line = line.strip()

            if declare_fun_match := DECLARE_FUN_PATTERN.fullmatch(line):
                var_name:  str = declare_fun_match.group("var")
                type_name: str = declare_fun_match.group("type")

                if "permitted" in var_name or                \
                        "choice" in var_name or              \
                        "CONTROL-FORWARDING" in var_name or  \
                        "DATA-FORWARDING" in var_name or     \
                        "reachable_" in var_name:
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
                        self.__inter_var_to_consts[var_exprnode] = const_true_exprnode
                    elif not var_result and var_not_result:
                        self.__inter_var_to_consts[var_exprnode] = const_false_exprnode
                    else:
                        self.__inter_var_to_consts[var_exprnode] = None
                        warn_if_false(False, "ExprParser.compute()",  \
                            f"Invalid evaluation about the variable {var_name}.")

                elif "FAILED-NODE" in var_name or  \
                        "FAILED-EDGE" in var_name:
                    if "Int" not in type_name:
                        fatal_error("ExprParser.compute()", "Unmatch variable type.")

                    failed_disable_const = f"(assert (= {var_name} 0))"
                    failed_enable_const  = f"(assert (= {var_name} 1))"

                    failed_disable_result =  \
                        self.__check_sat(self.__smt_encoding + failed_disable_const)
                    failed_enable_result  =  \
                        self.__check_sat(self.__smt_encoding + failed_enable_const)

                    failed_var_exprnode:     ExprNode = make_var(var_name)
                    failed_disable_exprnode: ExprNode = make_const("0")
                    failed_enable_exprnode:  ExprNode = make_const("1")

                    if failed_disable_result and not failed_enable_result:
                        self.__inter_var_to_consts[failed_var_exprnode] =  \
                            failed_disable_exprnode
                    elif not failed_disable_result and failed_enable_result:
                        self.__inter_var_to_consts[failed_var_exprnode] =  \
                            failed_enable_exprnode
                    else:
                        self.__inter_var_to_consts[failed_var_exprnode] = None
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
                        self.__inter_var_to_consts[var_history_exprnode] = const_history_exprnode
                    else:
                        fatal_error("ExprParser.compute()",  \
                            f"Invalid evaluation about the history variable {var_name}.")

            elif config_const_match := CONFIG_CONST_PATTERN.fullmatch(line):
                config_var_name:  str = ""
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
                self.__config_var_to_consts[var_config_exprnode] = const_config_exprnode

    def parse(self) -> None:
        """Parse a list of SMT-LIB lines and extract expression trees."""
        for line in self.__smt_lines:
            line = line.strip()
            if not (line.startswith("(assert") and line.endswith(")")):
                continue

            select_route_flag = line.endswith("))))))))")

            inner_expr = line[len("(assert"):-len(")")].strip()
            try:
                tokens = self.__tokenize(inner_expr)
                s_expr = self.__parse_sexpr(tokens)
                expr = self.__convert_to_expr_node(s_expr)
                simplified_expr = (
                    self.__simplify_expr(expr) if not select_route_flag else expr
                )
                self.__expr_nodes[simplified_expr] = select_route_flag
            except Exception as e:
                fatal_error("ExprParser.parse()", f"Parsing failed: {e}.")

        # Collect all deducable variable and replace it with constant / other variable.
        self.simplify()

    def __deduce_expr(self, expr: ExprNode) -> None:
        if expr.is_and():
            [self.__deduce_expr(sub_expr) for sub_expr in expr.args]
        elif expr.is_var():
            self.__temp_var_to_consts[expr] = make_const("true")
        elif expr.is_not() and expr.args[0].is_var():
            self.__temp_var_to_consts[expr.args[0]] = make_const("false")
        elif expr.is_equal() and expr.args[0].is_var() and expr.args[1].is_var():
            self.__temp_var_to_consts[expr.args[0]] = expr.args[1]
        elif expr.is_equal() and (expr.args[0].is_var() or expr.args[1].is_var()):
            if expr.args[0].is_var() and expr.args[1].is_const():
                self.__temp_var_to_consts[expr.args[0]] = expr.args[1]
            elif expr.args[1].is_var() and expr.args[0].is_const():
                self.__temp_var_to_consts[expr.args[1]] = expr.args[0]
            else:
                pass
        else:
            pass

    def simplify(self) -> None:
        while True:
            # Collect all deducable variable -> constant / other variable pairs.
            for expr, select_route_flag in self.__expr_nodes.items():
                if select_route_flag:  continue
                self.__deduce_expr(expr)

            # Break the loop if no new variable were deduced in this iteration.
            if not self.__temp_var_to_consts:  break

            # Repalce these variable with constant or other variable.
            self.__expr_nodes = {
                (
                    self.__simplify_expr(expr, self.__temp_var_to_consts)  \
                        if not flag else expr
                ): flag
                for expr, flag in self.__expr_nodes.items()
            }

            # Add deduced variable to the global deduced variable map for this iteration.
            self.__deduced_var_to_consts.update(self.__temp_var_to_consts)
            self.__temp_var_to_consts = {}

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

    def __simplify_expr(self, expr: ExprNode, 
                        var_to_consts: Dict[ExprNode, ExprNode] = None, 
                        flag: bool = False) -> ExprNode:
        """Simplify the ExprNode recursively, like z3 simplify()."""
        # Replace variables with deduced constants, recursively.
        replaced_args = [
            self.__replace_var(arg, var_to_consts)   \
                    if isinstance(arg, ExprNode) and arg.is_var() else arg
            for arg in expr.args
        ]

        # Simplify sub-expressions according to the following rules, recursively.
        simplified_args = [
            self.__simplify_expr(arg, var_to_consts)   \
                    if isinstance(arg, ExprNode) else arg 
            for arg in replaced_args
        ]

        # Simplification rules.
        if "and" == expr.op:
            if any(a.is_const_false() for a in simplified_args):
                return make_const("false")
            new_args = [a for a in simplified_args if not a.is_const_true()]
            if not new_args:          return make_const("true")
            elif 1 == len(new_args):  return new_args[0]
            else:                     return make_and(*new_args)

        elif "or" == expr.op:
            if any(a.is_const_true() for a in simplified_args):
                return make_const("true")
            new_args = [a for a in simplified_args if not a.is_const_false()]
            if not new_args:          return make_const("false")
            elif 1 == len(new_args):  return new_args[0]
            else:                     return make_or(*new_args)

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
                else:           return make_const("false")
                # warn_if_false(False, "ExprParser.__simplify_expr()", 
                #               f"Incorrect equality expression {expr}.")
            elif lhs.is_var() and rhs.is_var():
                if lhs == rhs:  return make_const("true")

        elif "not" == expr.op:
            cond = simplified_args[0]
            if cond.is_const():
                if "true" == cond.args[0]:     return make_const("false")
                elif "false" == cond.args[0]:  return make_const("true")

        return ExprNode(expr.op, simplified_args)

    def __replace_var(self, expr: ExprNode, 
                      var_to_consts: Dict[ExprNode, ExprNode] = None) -> ExprNode:
        if not expr.is_var():
            fatal_error("ExprParser.__replace_var()", "Not variable ExprNode.")

        if var_to_consts is None:
            if expr in self.__config_var_to_consts.keys() and  \
                    self.__config_var_to_consts[expr]:
                return self.__config_var_to_consts[expr]
            elif expr in self.__inter_var_to_consts.keys() and  \
                    self.__inter_var_to_consts[expr]:
                return self.__inter_var_to_consts[expr]
        else:
            if expr in var_to_consts.keys() and var_to_consts[expr]:
                return var_to_consts[expr]
        
        return expr

    def get_config_var_to_consts(self) -> Dict[ExprNode, ExprNode]:
        return self.__config_var_to_consts

    def get_inter_var_to_consts(self) -> Dict[ExprNode, ExprNode]:
        return self.__inter_var_to_consts

    def get_deduced_var_to_consts(self) -> Dict[ExprNode, ExprNode]:
        return self.__deduced_var_to_consts

    def get_var_to_consts(self) -> Dict[ExprNode, ExprNode]:
        return self.__config_var_to_consts | self.__inter_var_to_consts |   \
                self.__deduced_var_to_consts

    def get_expr_nodes(self) -> Dict[ExprNode, bool]:
        return self.__expr_nodes

    def print_var_to_consts(self, delimiter_flag: bool = False) -> None:
        for var, const in self.__config_var_to_consts.items():
            print(f"{var}: {const}")
        print("------------------------------------------------------------")
        for var, const in self.__inter_var_to_consts.items():
            print(f"{var}: {const}")
        print("------------------------------------------------------------")
        for var, const in self.__deduced_var_to_consts.items():
            print(f"{var}: {const}")
        if delimiter_flag:
            print("------------------------------------------------------------" +  \
                  "--------------------")

    def print_expr_nodes(self, delimiter_flag: bool = False) -> None:
        for expr in self.__expr_nodes:
            print(f"(assert {expr})")
        if delimiter_flag:
            print("------------------------------------------------------------" +  \
                  "--------------------")
