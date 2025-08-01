import re

# Match an SMT-LIB variable (possibly enclosed in pipes and escaped pipes)
VAR_REGEX = r'''
    (
        \|[^|]*?(?:\\\|[^|]*?)*\|                # quoted var like |xxx| or |x\|y|
        | [^\s()]+                               # or anything that is not space, (, )
    )
'''
VAR_PATTERN = re.compile(VAR_REGEX, re.VERBOSE)

# Match a configuration variable that start with "Config_"
CONFIG_VAR_REGEX = r'Config_[a-zA-Z0-9_]+'
CONFIG_VAR_PATTERN = re.compile(CONFIG_VAR_REGEX)

# Match constants: binary, hexadecimal, and decimal
CONST_REGEX = r'''
    (
        \#[bB][01]+                              # binary constant like #b0101
        | \#[xX][0-9a-fA-F]+                     # hexadecimal constant like #x123A
        | \d+                                    # plain decimal constant
    )
'''
CONST_PATTERN = re.compile(CONST_REGEX, re.VERBOSE)

# Match `(declare-fun <var> () <type>)` where <type> is BitVec, Bool, Int, or Real
DECLARE_FUN_REGEX = (
    r'\(declare-fun\s+'
    r'(?P<var>' + VAR_REGEX + r')\s*'            # Variable name
    r'\(\)\s*'                                   # Empty argument list ()
    r'(?P<type>\(\s*_+\s*BitVec\s+\d+\s*\)|Bool|Int|Real)'  # Type declaration
    r'\s*\)'
)
DECLARE_FUN_PATTERN = re.compile(DECLARE_FUN_REGEX, re.VERBOSE)

# Match configuration constraints
# (assert (= Config_xxx constant))
# (assert (not Config_xxx))
# (assert Config_xxx)
"""
CONFIG_CONST_REGEX = (
    r'\(assert\s+'                               # Starts with (assert
    r'(?:\(=|\(not)?\s*'                         # Optional (= or (not
    + CONFIG_VAR_REGEX + r'\b'                   # Configuration variable
)
"""
CONFIG_CONST_REGEX = (
    r'\(assert\s*'
    r'(?:'
        r'(?P<var1>Config_[a-zA-Z0-9_]+)'            # Case 1: (assert Config_xxx)
        r'|'
        r'\(not\s+(?P<var2>Config_[a-zA-Z0-9_]+)\)'  # Case 2: (assert (not Config_xxx))
        r'|'
        r'\(=\s+(?P<var3>Config_[a-zA-Z0-9_]+)\s+(?P<const>[^()\s]+)\)'  # Case 3: (assert (= Config_xxx const))
    r')'
    r'\s*\)'
)
CONFIG_CONST_PATTERN = re.compile(CONFIG_CONST_REGEX)

# Match configuration constraint `(assert Config_xxx)`
CONFIG_TRUE_REGEX = (
    r'\(assert\s+'                               # Opening assert
    r'(?P<var>' + CONFIG_VAR_REGEX + r')\s*'     # Config variable
    r'\)'                                        # Closing parenthesis
)
CONFIG_TRUE_PATTERN = re.compile(CONFIG_TRUE_REGEX)

# Match configuration constraint `(assert (not Config_xxx))`
CONFIG_FALSE_REGEX = (
    r'\(assert\s+\(not\s+'                       # Opening assert with not
    r'(?P<var>' + CONFIG_VAR_REGEX + r')\s*'     # Config variable
    r'\)\)'                                      # Closing parentheses
)
CONFIG_FALSE_PATTERN = re.compile(CONFIG_FALSE_REGEX)

# Match configuration constraint `(assert (= Config_xxx constant))`
CONFIG_EQUAL_CONST_REGEX = (
    r'\(assert\s+\(=\s+'                         # Opening assert with equality
    r'(?P<var>' + CONFIG_VAR_REGEX + r')\s+'     # Config variable
    r'(?P<const>[^()\s]+)\s*'                    # Constant value (non-parenthesis)
    r'\)\)'                                      # Closing parentheses
)
CONFIG_EQUAL_CONST_PATTERN = re.compile(CONFIG_EQUAL_CONST_REGEX)
