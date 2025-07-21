import re

# Match an SMT-LIB variable (possibly enclosed in pipes and escaped pipes)
VAR_REGEX = r'''
    (
        \|[^|]*?(?:\\\|[^|]*?)*\|                # quoted var like |xxx| or |x\|y|
        | [^\s()]+                               # or anything that is not space, (, )
    )
'''
VAR_PATTERN = re.compile(VAR_REGEX, re.VERBOSE)

# Match constants: binary, hex, decimal, with or without #
CONST_REGEX = r'''
    (
        \#[bB][01]+                              # binary constant like #b0101
        | \#[xX][0-9a-fA-F]+                     # hexadecimal constant like #x123A
        | \#?[0-9a-fA-F]+                        # hexadecimal constant like #123A
        | \d+                                    # plain decimal constant
    )
'''
CONST_PATTERN = re.compile(CONST_REGEX, re.VERBOSE)

# Match `(declare-fun <var> () <type>)` where <type> is BitVec, Bool, Int, or Real
DECLARE_FUN_REGEX = (
    r'\(declare-fun\s+'
    r'(?P<var>' + VAR_REGEX + r')\s*'            # Variable name
    r'\(\)\s*'                                   # Empty argument list ()
    r'(?P<type>\(_ BitVec \d+\)|Bool|Int|Real)'  # Type declaration
    r'\s*\)'
)
DECLARE_FUN_PATTERN = re.compile(DECLARE_FUN_REGEX)
