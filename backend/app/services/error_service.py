from typing import Tuple, Any, Dict
from enum import Enum
import traceback
import logging

class ErrorCode(Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    AUTH_FAILED = "AUTH_FAILED"
    CHALLENGE_EXPIRED = "CHALLENGE_EXPIRED"
    RATE_LIMIT = "RATE_LIMIT"
    CRYPTO_ERROR = "CRYPTO_ERROR"
    SERVER_ERROR = "SERVER_ERROR"

class SecurityError(Exception):
    def __init__(self, code: ErrorCode, message: str):
        self.code = code
        self.message = message
        super().__init__(self.message)

class ErrorService:
    @staticmethod
    def handle_auth_error(error: Exception) -> Tuple[Dict[str, Any], int]:
        """Enhanced error handling for authentication"""
        if isinstance(error, SecurityError):
            logging.warning(f"Security error: {error.code} - {error.message}")
            return {
                "error": error.message,
                "code": error.code.value,
                "type": "security_error"
            }, 401
            
        if isinstance(error, ValueError):
            logging.warning(f"Validation error: {str(error)}")
            return {
                "error": str(error),
                "code": ErrorCode.INVALID_REQUEST.value,
                "type": "validation_error"
            }, 400
            
        # Log unexpected errors with stack trace
        logging.error(f"Unexpected error: {str(error)}")
        logging.error(traceback.format_exc())
        
        return {
            "error": "Internal server error",
            "code": ErrorCode.SERVER_ERROR.value,
            "type": "server_error"
        }, 500

    @staticmethod
    def create_security_error(code: ErrorCode, message: str) -> SecurityError:
        """Create a security error"""
        return SecurityError(code, message) 