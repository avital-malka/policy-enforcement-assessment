import json

from uuid import uuid4
from functools import wraps

from log_config import logging
from errors import PolicyNotFoundError, RuleNotFoundError

decorator_logger = logging.getLogger(__name__)


def validate_policy_exists(func):
    """
    Decorator: Validates that a policy with the specified ID exists.
    """
    @wraps(func)
    def wrapper(self, policy_id: uuid4, *args, **kwargs):
        if policy_id not in self.policies_by_id:
            raise PolicyNotFoundError(policy_id)
        return func(self, policy_id, *args, **kwargs)
    return wrapper


def validate_rule_exists(func):
    """
    Decorator: Validates that a rule with the specified ID exists.
    """
    @wraps(func)
    def wrapper(self, rule_id: uuid4, *args, **kwargs):
        if rule_id not in self.rule_manager.rules_by_id:
            raise RuleNotFoundError(rule_id)
        return func(self, rule_id, *args, **kwargs)
    return wrapper


def validate_json_fields(expected_fields):
    """
    Decorator to validate expected fields in JSON input.

    Args:
        expected_fields (list[str]): List of expected field names.

    Returns:
        callable: Decorated function.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            """
            Wrapper function to validate JSON input fields.

            Args:
                *args: Additional positional arguments.

                **kwargs: Additional keyword arguments.
            Returns:
                Any: Result of the decorated function.

            Raises:
                ValueError: If JSON input is invalid or expected fields are missing.
            """
            json_input = args[0]
            if json_input is None:
                raise ValueError("Missing 'json_input' parameter.")
            try:
                data = json.loads(json_input)
                for field in expected_fields:
                    if field not in data:
                        raise ValueError(f"Field '{field}' is missing in JSON input.")
                return func(self, *args, **kwargs)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON input.")

        return wrapper

    return decorator


def log_function_calls(logger=None):
    """
    Decorator that logs function calls, arguments, and return values.

    Args:
        logger (logging.Logger, optional): The logger to use for logging. If not provided,
            the global logger will be used.

    Returns:
        function: Decorated function with logging capabilities.
    """
    if logger is None:
        logger = decorator_logger

    def decorator(func):
        """
        Decorator function that wraps the original function.

        Args:
            func (function): The original function to be decorated.

        Returns:
            function: Wrapped function with logging.
        """
        func_name = func.__name__

        @wraps(func)
        def log_func(*args, **kwargs):
            """
            Wrapped function that logs function calls, arguments,
            and return values.

            Args:
                *args: Positional arguments of the function.
                **kwargs: Keyword arguments of the function.

            Returns:
                The return value of the original function.
            """
            arg_names = func.__code__.co_varnames[:func.__code__.co_argcount]
            func_params = ', '.join('%s=%r' % entry for entry in list(zip(arg_names, args)) + list(kwargs.items()))

            logger.info('%s started: %s', func_name, func_params)

            ret = func(*args, **kwargs)

            logger.info('%s finished: %s. Return: %r', func_name, func_params, ret)
            return ret

        return log_func

    return decorator
