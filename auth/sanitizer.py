
from functools import wraps

import bleach  # type: ignore[import-untyped]


def sanitize_input(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sanitized_args = [bleach.clean(arg) if isinstance(arg, str) else arg for arg in args]
        sanitized_kwargs = {key: bleach.clean(value) if isinstance(value, str) else value for key, value in kwargs.items()}
        return func(*sanitized_args, **sanitized_kwargs)
    return wrapper
