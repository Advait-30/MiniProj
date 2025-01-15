from functools import wraps
from flask import request, abort
from app.services.rate_limit import RateLimiter

rate_limiter = RateLimiter()

def require_rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not rate_limiter.is_allowed(request.remote_addr):
            abort(429)
        return f(*args, **kwargs)
    return decorated_function 