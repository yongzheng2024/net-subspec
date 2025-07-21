from typing import List, Dict, Tuple
from netsubspec.utils.error import fatal_error
from netsubspec.core.expr_node import *

def parse_smt_constant(expr: ExprNode) -> int:
    if not expr.is_const():
        exit_information("parse_smt_constant()", "the ExprNode is not const")
    val = expr.args[0]
    if isinstance(val, str) and val.startswith("#x"):
        return int(val[2:], 16)
    elif isinstance(val, str) and val.startswith("#b"):
        return int(val[2:], 2)
    elif isinstance(val, str) and val.startswith("#"):
        return int(val[1:], 16)
    elif val == "false":
        return 0
    elif val == "true":
        return 1
    else:
        try:
            return int(val)
        except ValueError:
            fatal_error("parse_smt_constant()", 
                        f"Unrecognized SMT constant format: {val}.")

class ExprSimplifier:
    def __init__(self, expr_nodes: ExprList) -> None:
        self.__expr_nodes: ExprList = expr_nodes
        self.__const_ture = make_const("true")
        self.__const_false = make_const("false")
        self.__replace_const_rules: Dict[ExprNode, ExprNode] = {}
        self.__replace_range_rules: Dict[ExprNode, Tuple[int, int]] = {}
        self.__replace_expr_rules: Dict[ExprNode, ExprNode] = {}

    def replace_all(self) -> None:
        """Run constant replacement and simplification until convergence."""
        while True:
            for node in self.__expr_nodes:
                self.__collect_constant_rules(node)
            for node in self.__expr_nodes:
                self.__collect_equality_rules(node)

            self.print_replace_rules()
            print("-------------------------------------------------------------")

            if not self.__replace_const_rules:
                break

            for i, node in enumerate(self.__expr_nodes):
                node = self.__replace_expr(node)
                print(node)
                print(".............................................................")
                node = self.__simplify_expr(node)
                print(node)
                print("-------------------------------------------------------------")
                self.__expr_nodes[i] = node

            self.__clear_rules()
            print("=============================================================")

    def print_replace_rules(self) -> None:
        print("Collected constant rules:")
        for k, v in self.__replace_const_rules.items():
            print(f"  {k} → {v}")
        print("Collected range rules:")
        for k, (low, high) in self.__replace_range_rules.items():
            print(f"  {k} ∈ [{low}, {high}]")
        print("Collected expression rules:")
        for k, v in self.__replace_expr_rules.items():
            print(f"  {k} → {v}")

    def print_expr_nodes(self) -> None:
        for node in self.__expr_nodes:
            print(node)

    def get_expr_nodes(self) -> ExprList:
        return self.__expr_nodes

    def __collect_constant_rules(self, expr: ExprNode) -> None:
        if expr.op == "and":
            for sub in expr.args:
                self.__collect_constant_rules(sub)

        elif expr.op == "=":
            lhs, rhs = expr.args
            if lhs.is_var() and rhs.is_const():
                self.__replace_const_rules[lhs] = rhs
            elif rhs.is_var() and lhs.is_const():
                self.__replace_const_rules[rhs] = lhs

            elif lhs.is_bvand() and rhs.is_bvand():
                a1, m1 = lhs.args
                a2, m2 = rhs.args
                if m1.is_const() and m2.is_const() and m1.args[0] == m2.args[0]:
                    mask = parse_smt_constant(m1)
                    if a1.is_var() and a2.is_const():
                        var, val = a1, parse_smt_constant(a2)
                    elif a1.is_const() and a2.is_var():
                        var, val = a2, parse_smt_constant(a1)
                    else:
                        return
                    base = val & mask
                    upper = base | (~mask & 0xffffffff)
                    self.__replace_range_rules[var] = (hex(base), hex(upper))
                    self.__replace_const_rules[var] = make_const(f"#x{base:x}")

        elif expr.is_var():
            self.__replace_const_rules[expr] = self.__const_ture
        elif expr.op == "not" and expr.args[0].is_var():
            self.__replace_const_rules[expr.args[0]] = self.__const_false

    def __collect_equality_rules(self, expr: ExprNode) -> None:
        if expr.op == "and":
            for sub in expr.args:
                self.__collect_equality_rules(sub)

        elif expr.op == "=":
            lhs, rhs = expr.args
            if lhs.is_var() and rhs.is_var():
                if lhs in self.__replace_const_rules:
                    self.__replace_const_rules[rhs] = self.__replace_const_rules[lhs]
                elif rhs in self.__replace_const_rules:
                    self.__replace_const_rules[lhs] = self.__replace_const_rules[rhs]

    def __clear_rules(self) -> None:
        self.__replace_const_rules.clear()
        self.__replace_range_rules.clear()
        self.__replace_expr_rules.clear()

    def __replace_expr(self, expr: ExprNode) -> ExprNode:
        if not isinstance(expr, ExprNode):
            return expr

        replaced_args = [self.__replace_expr(arg) for arg in expr.args]
        new_expr = ExprNode(expr.op, replaced_args)

        if new_expr in self.__replace_const_rules:
            return self.__replace_const_rules[new_expr]
        if new_expr in self.__replace_expr_rules:
            return self.__replace_expr_rules[new_expr]
        return new_expr

    def __simplify_expr(self, expr: ExprNode) -> ExprNode:
        if expr.is_leaf():  # is_var() or is_const()
            return expr

        args = [self.__simplify_expr(arg) for arg in expr.args]
        op = expr.op

        if op == "and":
            if any(a.is_const_false() for a in args):
                return self.__const_false
            args = [a for a in args if not a.is_const_true()]
            return self.__simplify_flat(op, args)

        elif op == "or":
            if any(a.is_const_true() for a in args):
                return self.__const_ture
            args = [a for a in args if not a.is_const_false()]
            return self.__simplify_flat(op, args)

        elif op == "not":
            if args[0].is_const_true():
                return self.__const_false
            if args[0].is_const_false():
                return self.__const_ture

        elif op == "ite":
            cond, then_, else_ = args
            if cond.is_const_true():
                return then_
            if cond.is_const_false():
                return else_

        elif op == "=>":
            cond, then_ = args
            if cond.is_const_true():
                return then_
            if cond.is_const_false():
                return self.__const_ture

        elif op == "=": 
            if all(a.is_const() for a in args):
                return self.__const_ture  \
                    if args[0].args[0] == args[1].args[0] else self.__const_false

        elif op in {"+", "-", "*", "/"}: 
            if all(a.is_const() for a in args):
                a, b = map(parse_smt_constant, args)
                result = eval(f"{a} {op} {b}")
                return make_const(str(result))

        elif op in {"<", "<=", ">", ">="}:
            if all(a.is_const() for a in args):
                a, b = map(parse_smt_constant, args)
                return self.__const_ture if eval(f"{a} {op} {b}") else self.__const_false

        elif op in {"bvand", "bvor"}: 
            if all(a.is_const() for a in args):
                a, b = map(parse_smt_constant, args)
                result = a & b if op == "bvand" else a | b
                return make_const(f"#x{result:x}")

        elif op == "bvnot": 
            if args[0].is_const():
                val = parse_smt_constant(args[0])
                result = ~val & 0xffffffff
                return make_const(f"#x{result:x}")

        elif op in {"bvult", "bvule", "bvugt", "bvuge"}: 
            if all(a.is_const() for a in args):
                a, b = map(parse_smt_constant, args)
                comp = {
                    "bvult": a < b,
                    "bvule": a <= b,
                    "bvugt": a > b,
                    "bvuge": a >= b,
                }
                return self.__const_ture if comp[op] else self.__const_false

        else:
            fatal_error("ExprSimplify.__simplify_expr()", 
                        f"Unsupported ExprNode operation signal {op}.")
            

        return ExprNode(op, args)

    def __simplify_flat(self, op: str, args: ExprList) -> ExprNode:
        if not args:
            return self.__const_ture if op == "and" else self.__const_false
        if len(args) == 1:
            return args[0]
        return ExprNode(op, args)
