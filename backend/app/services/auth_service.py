from datetime import datetime
import os
from typing import Dict, Optional, Tuple
from .crypto_service import CryptoService
from .error_service import ErrorService, ErrorCode

class AuthService:
    def __init__(self):
        self.crypto = CryptoService()
        # In-memory session storage (DB team will handle persistence)
        self._sessions = {}
    
    def init_authentication(self, pseudo_identity: str) -> Dict[str, str]:
        """
        Initialize authentication process
        Returns challenge and server's public key
        """
        try:
            # Create challenge for this pseudo-identity
            challenge_data = self.crypto.create_challenge(pseudo_identity)
            
            return {
                'status': 'success',
                'challenge': challenge_data['challenge'],
                'server_signature': challenge_data['signature'],
                'server_public_key': challenge_data['server_public']
            }
            
        except Exception as e:
            raise ErrorService.create_security_error(
                ErrorCode.CRYPTO_ERROR,
                "Failed to initialize authentication"
            )
    
    def verify_authentication(
        self,
        pseudo_identity: str,
        challenge_response: str,
        client_proof: str,
        client_signature: str
    ) -> Dict[str, str]:
        """
        Verify client's challenge response and establish session
        """
        try:
            # Verify challenge response and get session key
            verified, session_key = self.crypto.verify_challenge_response(
                pseudo_identity,
                challenge_response,
                client_proof
            )
            
            if not verified or not session_key:
                raise ErrorService.create_security_error(
                    ErrorCode.AUTH_FAILED,
                    "Invalid challenge response"
                )
            
            # Create session
            session_id = os.urandom(32).hex()
            session = {
                'session_id': session_id,
                'pseudo_identity': pseudo_identity,
                'session_key': session_key,
                'created_at': datetime.utcnow(),
                'last_used': datetime.utcnow()
            }
            
            # Store session (DB team will handle persistence)
            self._sessions[session_id] = session
            
            # Encrypt session data for client
            encrypted_session = self.crypto.encrypt_data(
                session_id.encode(),
                session_key
            )
            
            return {
                'status': 'success',
                'session_token': encrypted_session['ciphertext'],
                'session_nonce': encrypted_session['nonce']
            }
            
        except Exception as e:
            if isinstance(e, ErrorService.SecurityError):
                raise e
            raise ErrorService.create_security_error(
                ErrorCode.CRYPTO_ERROR,
                "Authentication verification failed"
            )
    
    def validate_session(self, session_id: str) -> Tuple[bool, Optional[Dict]]:
        """
        Validate an existing session
        Returns (is_valid, session_data)
        """
        session = self._sessions.get(session_id)
        if not session:
            return False, None
            
        # Check session age
        age = (datetime.utcnow() - session['created_at']).total_seconds()
        if age > 3600:  # 1 hour timeout
            del self._sessions[session_id]
            return False, None
            
        # Update last used time
        session['last_used'] = datetime.utcnow()
        return True, session
    
    def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate a session (logout)
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False 