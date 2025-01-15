from typing import Dict, Any

class ValidationService:
    @staticmethod
    def validate_challenge_request(data: Dict[str, Any]) -> bool:
        """Validate challenge request data"""
        required = ['pseudo_identity']
        return all(k in data for k in required)

    @staticmethod
    def validate_auth_request(data: Dict[str, Any]) -> bool:
        """Validate authentication request data"""
        required = ['pseudo_identity', 'challenge_response', 'client_proof']
        return all(k in data for k in required) 