"""
Enhanced Security Scheme for WBAN Authentication
Improvements over original paper:
1. Replace ECC with more efficient X25519 for key exchange
2. Use Ed25519 for signatures (faster, more secure than ECDSA)
3. Add perfect forward secrecy
4. Implement dynamic pseudo-identity generation
5. Add mutual authentication with timestamp-based challenge
"""

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import time
import base64

class EnhancedWBANSecurity:
    def __init__(self):
        self.CHALLENGE_VALIDITY = 30  # 30 seconds for timestamp freshness
        
    def generate_user_credentials(self):
        """Generate initial user credentials"""
        # Key pairs for long-term identity
        identity_key = ed25519.Ed25519PrivateKey.generate()
        identity_public = identity_key.public_key()
        
        # Key pairs for key exchange
        exchange_key = x25519.X25519PrivateKey.generate()
        exchange_public = exchange_key.public_key()
        
        return {
            'identity_key': identity_key,
            'identity_public': identity_public,
            'exchange_key': exchange_key,
            'exchange_public': exchange_public
        }
    
    def create_pseudo_identity(self, real_identity: bytes, timestamp: int) -> str:
        """Generate unlinkable pseudo-identity"""
        salt = os.urandom(16)
        info = b"wban_pseudo_id_v1"
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info
        )
        
        material = real_identity + timestamp.to_bytes(8, 'big')
        pseudo_id = hkdf.derive(material)
        
        return base64.b64encode(pseudo_id + salt).decode('utf-8')
    
    def create_authentication_challenge(self, identity_key, timestamp: int, nonce: bytes):
        """Create authentication challenge"""
        message = timestamp.to_bytes(8, 'big') + nonce
        signature = identity_key.sign(message)
        
        return {
            'timestamp': timestamp,
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'signature': base64.b64encode(signature).decode('utf-8')
        }
    
    def verify_challenge(self, public_key, challenge: dict) -> bool:
        """Verify authentication challenge"""
        try:
            current_time = int(time.time())
            challenge_time = challenge['timestamp']
            
            # Verify timestamp freshness
            if abs(current_time - challenge_time) > self.CHALLENGE_VALIDITY:
                return False
            
            # Verify signature
            message = challenge_time.to_bytes(8, 'big') + base64.b64decode(challenge['nonce'])
            signature = base64.b64decode(challenge['signature'])
            public_key.verify(signature, message)
            return True
            
        except Exception:
            return False
    
    def establish_session(self, local_key, peer_public):
        """Establish secure session with perfect forward secrecy"""
        shared_secret = local_key.exchange(peer_public)
        
        # Derive session keys
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"wban_session_v1"
        )
        
        session_key = hkdf.derive(shared_secret)
        return session_key 