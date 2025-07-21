import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def warn_if_false(condition: bool, function_name: str, message: str) -> None:
    """
    Logs a warning if the condition is False.

    Args:
        condition (bool): The condition to check.
        function_name (str): Name of the function reporting the warning.
        message (str): Warning message to display.
    """
    if not condition:
        logging.warning(f"{function_name}: {message}")

def exit_if_false(condition: bool, function_name: str, message: str) -> None:
    """
    Logs an error and exits if the condition is False.

    Args:
        condition (bool): The condition to check.
        function_name (str): Name of the function reporting the error.
        message (str): Error message to display.
    """
    if not condition:
        logging.error(f"{function_name}: {message}")
        sys.exit(1)

def fatal_error(function_name: str, message: str) -> None:
    """
    Always logs an error and exits the program.

    Args:
        function_name (str): Name of the function reporting the error.
        message (str): Error message to display.
    """
    exit_if_false(False, function_name, message)
