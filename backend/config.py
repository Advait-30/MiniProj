import os
from datetime import timedelta

class Config:
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    
    # Authentication
    CHALLENGE_TIMEOUT = 30  # seconds
    SESSION_TIMEOUT = 1800  # 30 minutes
    
    # Crypto
    PSEUDO_ID_LENGTH = 32
    NONCE_LENGTH = 32
    
    # Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
    } 