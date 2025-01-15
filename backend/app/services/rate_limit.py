from flask import request
import time

class RateLimiter:
    def __init__(self):
        self._requests = {}
        self.WINDOW_SIZE = 60  # 1 minute
        self.MAX_REQUESTS = 30

    def is_allowed(self, identifier: str) -> bool:
        """Check if request is within rate limits"""
        current = time.time()
        if identifier not in self._requests:
            self._requests[identifier] = []
        
        # Clean old requests
        self._requests[identifier] = [
            req_time for req_time in self._requests[identifier]
            if current - req_time < self.WINDOW_SIZE
        ]
        
        if len(self._requests[identifier]) >= self.MAX_REQUESTS:
            return False
            
        self._requests[identifier].append(current)
        return True 