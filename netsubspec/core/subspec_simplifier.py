from typing import Set, Dict

from netsubspec.utils.error import *
from netsubspec.core.expr_node import *

class SubspecSimplifier:
    def __init__(self, 
                 var_vals: Dict[ExprNode, ExprNode],
                 var_defs: Dict[ExprNode, Set[ExprNode]],
                 final_vars: Dict[ExprNode, ExprNode],
                 target_vars: Set[ExprNode]) -> None:
        # The value of intermediate variables.
        # None meaning the variable don't have value.
        self.__var_vals: Dict[ExprNode, ExprNode] = var_vals
        # The definitions of intermediate variables.
        self.__var_defs: Dict[ExprNode, Set[ExprNode]] = var_defs
        # The final proprety variables.
        self.__final_vars: Dict[ExprNode, ExprNode] = final_vars
        # The target configuration field variables.
        self.__target_vars: Set[ExprNode] = target_vars

        # Deduced variables' value accoridng to backward traversal.
        self.__var_deduced: Dict[ExprNode, ExprNode] = {}

    def compute_subspec(self) -> None:
        

    def deduce_variables(self, var: ExprNode, val_deduced: ExprNode, 
                         defs: Set[ExprNode]) -> None:
        cond_var_deduced: Dict[ExprNode, Set[ExprNode]] = {}

        # Collect deducable variable and its value to 
        for var_def in defs:
            if "=" == var_def.op:
            elif "ite" == var_def.op:
            elif "=>" == var_def.op:
            else:
                fatal_error("SubspecSimplifier.deduce_variables()", 
                            f"Unsupported variable's definitation: {var_def}")
