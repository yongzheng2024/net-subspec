from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Union

@dataclass
class ExprNode:
    def __init__(self, op: str, args: List[Union[ExprNode, str]]) -> None:
        self.op: str = op
        self.args: List[Union[ExprNode, str]] = args

    def __repr__(self) -> str:
        return f"({self.op} {' '.join(map(str, self.args))})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExprNode):
            return NotImplemented
        return self.op == other.op and self.args == other.args

    def __hash__(self) -> int:
        return hash((self.op, tuple(self.args)))

    def is_var(self) -> bool:
        return self.op == "var" and len(self.args) == 1

    def is_const(self) -> bool:
        return self.op == "const" and len(self.args) == 1

    def is_leaf(self) -> bool:
        return self.is_var() or self.is_const()

    def is_expr(self) -> bool:
        return not self.is_leaf()

    def is_ite(self) -> bool:
        return self.op == "ite" and len(self.args) == 3

    def is_implies(self) -> bool:
        return self.op == "=>" and len(self.args) == 2

    def is_bvand(self) -> bool:
        return self.op == "bvand" and len(self.args) == 2

    def is_const_true(self) -> bool:
        return self.op == "const" and self.args == ["true"]

    def is_const_false(self) -> bool:
        return self.op == "const" and self.args == ["false"]


# Construction helpers
def make_var(name: str) -> ExprNode:
    return ExprNode("var", [name])

def make_const(val: str) -> ExprNode:
    return ExprNode("const", [val])

def make_equal(lhs: ExprNode, rhs: ExprNode) -> ExprNode:
    assert lhs is not None, "make_equal(): Left ExprNode is None."
    assert rhs is not None, "make_equal(): Right ExprNode is None."
    return ExprNode("=", [lhs, rhs])

def make_and(*args: Optional[ExprNode]) -> Optional[ExprNode]:
    valid_args = [a for a in args if a is not None]
    if not valid_args:
        return None
    if len(valid_args) == 1:
        return valid_args[0]
    return ExprNode("and", valid_args)


# Type alias for brevity
ExprList = List[ExprNode]
