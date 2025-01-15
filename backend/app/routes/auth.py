from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from ..services.auth_service import AuthService
from ..services.error_service import ErrorService, ErrorCode
from ..services.validation_service import ValidationService

auth_bp = Blueprint('auth', __name__)
auth_service = AuthService()
validation_service = ValidationService()

@auth_bp.route('/init', methods=['POST'])
def init_auth():
    """
    Initialize authentication process
    Expects: { pseudo_identity: string }
    """
    try:
        data = request.get_json()
        if not validation_service.validate_init_request(data):
            raise ErrorService.create_security_error(
                ErrorCode.INVALID_REQUEST,
                "Invalid request data"
            )

        result = auth_service.init_authentication(data['pseudo_identity'])
        return jsonify(result), 200

    except Exception as e:
        error_response, status_code = ErrorService.handle_auth_error(e)
        return jsonify(error_response), status_code

@auth_bp.route('/verify', methods=['POST'])
def verify_auth():
    """
    Verify authentication challenge response
    Expects: {
        pseudo_identity: string,
        challenge_response: string,
        client_proof: string,
        client_signature: string
    }
    """
    try:
        data = request.get_json()
        if not validation_service.validate_auth_response(data):
            raise ErrorService.create_security_error(
                ErrorCode.INVALID_REQUEST,
                "Invalid response data"
            )

        result = auth_service.verify_authentication(
            data['pseudo_identity'],
            data['challenge_response'],
            data['client_proof'],
            data['client_signature']
        )

        # Create JWT token if authentication successful
        if result['status'] == 'success':
            access_token = create_access_token(
                identity=data['pseudo_identity'],
                additional_claims={
                    'session_token': result['session_token'],
                    'session_nonce': result['session_nonce']
                }
            )
            result['access_token'] = access_token

        return jsonify(result), 200

    except Exception as e:
        error_response, status_code = ErrorService.handle_auth_error(e)
        return jsonify(error_response), status_code

@auth_bp.route('/validate', methods=['POST'])
@jwt_required()
def validate_session():
    """Validate current session"""
    try:
        current_user = get_jwt_identity()
        session_id = request.headers.get('X-Session-ID')
        
        if not session_id:
            raise ErrorService.create_security_error(
                ErrorCode.INVALID_REQUEST,
                "Missing session ID"
            )

        is_valid, session_data = auth_service.validate_session(session_id)
        
        if not is_valid:
            raise ErrorService.create_security_error(
                ErrorCode.AUTH_FAILED,
                "Invalid or expired session"
            )

        return jsonify({
            'status': 'success',
            'valid': True,
            'pseudo_identity': current_user
        }), 200

    except Exception as e:
        error_response, status_code = ErrorService.handle_auth_error(e)
        return jsonify(error_response), status_code

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout and invalidate session"""
    try:
        session_id = request.headers.get('X-Session-ID')
        if not session_id:
            raise ErrorService.create_security_error(
                ErrorCode.INVALID_REQUEST,
                "Missing session ID"
            )

        if auth_service.invalidate_session(session_id):
            return jsonify({
                'status': 'success',
                'message': 'Logged out successfully'
            }), 200
        else:
            raise ErrorService.create_security_error(
                ErrorCode.AUTH_FAILED,
                "Invalid session"
            )

    except Exception as e:
        error_response, status_code = ErrorService.handle_auth_error(e)
        return jsonify(error_response), status_code 