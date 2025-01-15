from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidKey
import os
import base64
import time
from typing import Dict, Tuple, Optional

class CryptoService:
    def __init__(self):
        # Constants
        self.AUTH_INFO = b"healthcare_auth_v1"
        self.ENCRYPTION_INFO = b"healthcare_encryption_v1"
        self.CHALLENGE_TIMEOUT = 300  # 5 minutes
        
        # Generate server keys on initialization
        self._init_server_keys()
        
        # In-memory challenge storage (DB team will handle persistence)
        self._active_challenges = {}
    
    def _init_server_keys(self) -> None:
        """Initialize server's long-term keys"""
        # For signatures (Ed25519)
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.verify_key = self.signing_key.public_key()
        
        # For key exchange (X25519)
        self.exchange_key = x25519.X25519PrivateKey.generate()
        self.exchange_public = self.exchange_key.public_key()
    
    def create_challenge(self, pseudo_identity: str) -> Dict[str, str]:
        """Create authentication challenge"""
        timestamp = int(time.time())
        nonce = os.urandom(32)
        
        # Create challenge material
        challenge_material = nonce + timestamp.to_bytes(8, 'big')
        
        # Sign the challenge
        signature = self.signing_key.sign(challenge_material)
        
        # Store challenge for verification
        self._active_challenges[pseudo_identity] = {
            'nonce': nonce,
            'timestamp': timestamp,
            'material': challenge_material
        }
        
        return {
            'challenge': base64.b64encode(challenge_material).decode('utf-8'),
            'signature': base64.b64encode(signature).decode('utf-8'),
            'server_public': base64.b64encode(
                self.exchange_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ).decode('utf-8')
        }
    
    def verify_challenge_response(
        self, 
        pseudo_identity: str, 
        response: str, 
        client_proof: str
    ) -> Tuple[bool, Optional[bytes]]:
        """Verify challenge response and generate session key"""
        stored = self._active_challenges.get(pseudo_identity)
        if not stored:
            return False, None
            
        try:
            # Check timestamp
            current_time = int(time.time())
            if current_time - stored['timestamp'] > self.CHALLENGE_TIMEOUT:
                return False, None
            
            # Verify response
            response_data = base64.b64decode(response)
            if not response_data.startswith(stored['nonce']):
                return False, None
            
            # Generate shared secret
            client_public_raw = base64.b64decode(client_proof)
            client_public = x25519.X25519PublicKey.from_public_bytes(client_public_raw)
            
            shared_secret = self.exchange_key.exchange(client_public)
            
            # Derive session key
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=stored['nonce'],
                info=self.ENCRYPTION_INFO
            ).derive(shared_secret)
            
            # Clean up challenge
            del self._active_challenges[pseudo_identity]
            
            return True, session_key
            
        except (ValueError, InvalidKey):
            return False, None
    
    def encrypt_data(self, data: bytes, key: bytes) -> Dict[str, str]:
        """Encrypt data using ChaCha20-Poly1305"""
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key)
        timestamp = int(time.time()).to_bytes(8, 'big')
        
        ciphertext = cipher.encrypt(nonce, data, timestamp)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'timestamp': int.from_bytes(timestamp, 'big')
        } 