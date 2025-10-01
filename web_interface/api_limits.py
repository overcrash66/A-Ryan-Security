from functools import wraps
from flask import request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def api_rate_limit(limits=None):
    """
    Decorator for API rate limiting
    :param limits: List of rate limit strings (e.g. ["100/hour", "1000/day"])
    """
    if limits is None:
        limits = ["100/hour", "1000/day"]  # Default API limits

    def decorator(f):
        @wraps(f)
        @limiter.limit(limits)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator