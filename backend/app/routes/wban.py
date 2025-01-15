from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..services.wban_crypto_service import WBANCryptoService
from datetime import datetime

wban_bp = Blueprint('wban', __name__)
wban_crypto = WBANCryptoService()

# In-memory storage for demo
wban_data_store = []

@wban_bp.route('/wban/data', methods=['POST'])
@jwt_required()
def upload_wban_data():
    """Upload encrypted WBAN sensor data"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    required_fields = ['device_id', 'data_type', 'data']
    if not all(k in data for k in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        # Encrypt the WBAN data
        encrypted = wban_crypto.encrypt_wban_data(
            data['data'].encode(),
            wban_crypto.derive_session_key(user_id)
        )
        
        # Store encrypted data in memory (for demo)
        wban_data = {
            'user_id': user_id,
            'device_id': data['device_id'],
            'data_type': data['data_type'],
            'encrypted_data': encrypted['ciphertext'],
            'nonce': encrypted['nonce'],
            'timestamp': datetime.fromtimestamp(encrypted['timestamp']),
            'session_id': request.headers.get('X-Session-ID'),
            'data_category': data.get('category'),
            'anonymized_location': data.get('location')
        }
        
        wban_data_store.append(wban_data)
        
        return jsonify({'message': 'Data uploaded successfully'}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500 