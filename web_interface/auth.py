from functools import wraps
from flask import jsonify, request, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from models import User, db, AuditLog
from datetime import datetime

def log_api_access(user_id, endpoint, status_code):
    """Log API access to audit log."""
    log = AuditLog(
        user_id=user_id,
        action='api_access',
        resource_type='api_endpoint',
        resource_id=None,
        details=f'Accessed {endpoint}',
        ip_address=request.remote_addr
    )
    db.session.add(log)
    try:
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to log API access: {e}")
        db.session.rollback()

def api_key_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({"msg": "API key is missing"}), 401
        
        user = User.query.filter_by(api_key=api_key).first()
        if not user or not user.is_api_key_valid():
            return jsonify({"msg": "Invalid or expired API key"}), 401
        
        try:
            result = fn(*args, **kwargs)
            log_api_access(user.id, request.endpoint, 200)
            return result
        except Exception as e:
            log_api_access(user.id, request.endpoint, 500)
            raise
            
    return wrapper

def jwt_or_api_key_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # First try API key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            user = User.query.filter_by(api_key=api_key).first()
            if user and user.is_api_key_valid():
                log_api_access(user.id, request.endpoint, 200)
                return fn(*args, **kwargs)

        # Then try JWT
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            current_user = User.query.get(int(user_id)) if user_id else None
            if current_user:
                log_api_access(current_user.id, request.endpoint, 200)
                return fn(*args, **kwargs)
        except Exception as e:
            current_app.logger.error(f"JWT verification failed: {e}")

        return jsonify({"msg": "Valid authentication required"}), 401
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # First try API key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            user = User.query.filter_by(api_key=api_key).first()
            if user and user.is_api_key_valid():
                if user.role == 'admin':
                    log_api_access(user.id, request.endpoint, 200)
                    return fn(*args, **kwargs)
                return jsonify({"msg": "Admin access required"}), 403

        # Then try JWT
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            current_user = User.query.get(int(user_id)) if user_id else None
            if current_user and current_user.role == 'admin':
                log_api_access(current_user.id, request.endpoint, 200)
                return fn(*args, **kwargs)
            return jsonify({"msg": "Admin access required"}), 403
        except Exception as e:
            current_app.logger.error(f"JWT verification failed: {e}")

        return jsonify({"msg": "Valid admin authentication required"}), 401
    return wrapper