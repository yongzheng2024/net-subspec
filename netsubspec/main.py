import sys

from netsubspec.core.expr_node import ExprNode, ExprList
from netsubspec.pipeline.replace_constant import run_pipeline

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m your_project.main /your/path/to/work/directory")
        exit(1)

    path = sys.argv[1]
    run_pipeline(path)
