from datetime import datetime
import os
import time
from .security_scheme import EnhancedWBANSecurity

class WBANAuthFlow:
    def __init__(self):
        self.security = EnhancedWBANSecurity()
    
    async def initiate_authentication(self, user_id: str):
        """Step 1: Initiate authentication"""
        timestamp = int(time.time())
        nonce = os.urandom(32)
        
        # Generate new pseudo-identity for this session
        pseudo_id = self.security.create_pseudo_identity(
            user_id.encode(),
            timestamp
        )
        
        # Create authentication challenge
        challenge = self.security.create_authentication_challenge(
            self.identity_key,
            timestamp,
            nonce
        )
        
        return {
            'pseudo_id': pseudo_id,
            'challenge': challenge
        }
    
    async def verify_authentication(self, challenge_response: dict):
        """Step 2: Verify authentication response"""
        if not self.security.verify_challenge(
            self.peer_public_key,
            challenge_response
        ):
            raise ValueError("Invalid authentication")
        
        # Generate ephemeral key pair for perfect forward secrecy
        ephemeral_keys = self.security.generate_user_credentials()
        
        # Establish session
        session_key = self.security.establish_session(
            ephemeral_keys['exchange_key'],
            self.peer_exchange_public
        )
        
        return {
            'session_key': session_key,
            'ephemeral_public': ephemeral_keys['exchange_public']
        } 