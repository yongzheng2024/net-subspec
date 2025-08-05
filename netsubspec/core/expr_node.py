from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Union

@dataclass
class ExprNode:
    def __init__(self, op: str, args: List[Union[ExprNode, str]]) -> None:
        self.op: str = op
        self.args: List[Union[ExprNode, str]] = args

    def __repr__(self) -> str:
        if self.is_var() or self.is_const():
            return  f"{self.args[0]}"
        return f"({self.op} {' '.join(map(str, self.args))})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExprNode):
            return NotImplemented
        return self.op == other.op and self.args == other.args

    def __hash__(self) -> int:
        return hash((self.op, tuple(self.args)))

    def is_var(self) -> bool:
        return "var" == self.op and 1 == len(self.args)

    def is_const(self) -> bool:
        return "const" == self.op and 1 == len(self.args)

    def is_leaf(self) -> bool:
        return self.is_var() or self.is_const()

    def is_expr(self) -> bool:
        return not self.is_leaf()

    def is_not(self) -> bool:
        return "not" == self.op

    def is_and(self) -> bool:
        return "and" == self.op

    def is_or(self) -> bool:
        return "or" == self.op

    def is_equal(self) -> bool:
        return "=" == self.op

    def is_ite(self) -> bool:
        return "ite" == self.op and 3 == len(self.args)

    def is_implies(self) -> bool:
        return "=>" == self.op and 2 == len(self.args)

    def is_bvand(self) -> bool:
        return "bvand" == self.op and 2 == len(self.args)

    def is_const_true(self) -> bool:
        return "const" == self.op and ["true"] == self.args

    def is_const_false(self) -> bool:
        return "const" == self.op and ["false"] == self.args

    def is_reachable_id(self) -> bool:
        return "var" == self.op and "reachable-id" in self.args[0]


# Construction helpers
def make_var(name: str) -> ExprNode:
    return ExprNode("var", [name])

def make_const(val: str) -> ExprNode:
    return ExprNode("const", [val])

def make_not(expr: ExprNode) -> ExprNode:
    return ExprNode("not", [expr])

def make_equal(lhs: ExprNode, rhs: ExprNode) -> ExprNode:
    assert lhs is not None, "make_equal(): Left ExprNode is None."
    assert rhs is not None, "make_equal(): Right ExprNode is None."
    return ExprNode("=", [lhs, rhs])

def make_and_or(is_and: bool, *args: Optional[ExprNode]) -> Optional[ExprNode]:
    valid_args = [a for a in args if a is not None]
    if not valid_args:
        return None
    if len(valid_args) == 1:
        return valid_args[0]
    if is_and:  return ExprNode("and", valid_args)
    else:       return ExprNode("or", valid_args)

def make_and(*args: Optional[ExprNode]) -> Optional[ExprNode]:
    return make_and_or(True, *args)

def make_or(*args: Optional[ExprNode]) -> Optional[ExprNode]:
    return make_and_or(False, *args)


# Type alias for brevity
ExprList = List[ExprNode]
