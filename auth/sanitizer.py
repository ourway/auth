
from functools import wraps

import bleach  # type: ignore[import-untyped]
from flask import abort


def sanitize_input(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        values = list(args) + list(kwargs.values())
        if any(isinstance(value, str) and "\x00" in value for value in values):
            abort(400, description="Path parameters must not contain NUL characters.")
        sanitized_args = [bleach.clean(arg) if isinstance(arg, str) else arg for arg in args]
        sanitized_kwargs = {key: bleach.clean(value) if isinstance(value, str) else value for key, value in kwargs.items()}
        return func(*sanitized_args, **sanitized_kwargs)
    return wrapper
