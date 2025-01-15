from enum import Enum

class AuthenticationStatus(Enum):
    PENDING = "pending"
    CHALLENGED = "challenged"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"

CRYPTO_CONSTANTS = {
    'CHALLENGE_TIMEOUT': 30,  # seconds
    'SESSION_TIMEOUT': 1800,  # 30 minutes
    'NONCE_SIZE': 32,
    'KEY_SIZE': 32
} 