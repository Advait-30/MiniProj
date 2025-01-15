from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import base64
import time

class WBANCryptoService:
    def __init__(self):
        self.AUTH_INFO = b"wban_auth_v1"
        self.DATA_INFO = b"wban_data_v1"
        self.ID_INFO = b"wban_id_v1"
    
    def generate_dynamic_pseudo_identity(self, user_id: str, timestamp: int) -> str:
        """Generate unlinkable pseudo-identity for each session"""
        # Combine user_id with timestamp and random salt
        salt = os.urandom(16)
        material = f"{user_id}:{timestamp}".encode() + salt
        
        # Use HKDF to derive a new pseudo-identity
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=self.ID_INFO
        )
        pseudo_id = hkdf.derive(material)
        return base64.b64encode(pseudo_id).decode('utf-8')
    
    def encrypt_wban_data(self, data: bytes, key: bytes) -> dict:
        """Encrypt WBAN sensor data with ChaCha20-Poly1305"""
        # ChaCha20-Poly1305 is more suitable for constrained devices than AES
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key)
        
        # Add timestamp for freshness
        timestamp = int(time.time()).to_bytes(8, 'big')
        associated_data = timestamp
        
        # Encrypt data
        ciphertext = cipher.encrypt(nonce, data, associated_data)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'timestamp': int.from_bytes(timestamp, 'big')
        }
    
    def decrypt_wban_data(self, encrypted_data: dict, key: bytes) -> bytes:
        """Decrypt WBAN sensor data"""
        cipher = ChaCha20Poly1305(key)
        
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        timestamp = encrypted_data['timestamp'].to_bytes(8, 'big')
        
        return cipher.decrypt(nonce, ciphertext, timestamp) 