import logging
import traceback
from functools import wraps
from flask import jsonify, current_app, request, g
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass

class ValidationError(SecurityError):
    """Exception for input validation errors."""
    pass

class ScanError(SecurityError):
    """Exception for scanning operation errors."""
    pass

class DatabaseError(SecurityError):
    """Exception for database operation errors."""
    pass

def handle_security_error(error):
    """Handle security-related errors consistently."""
    error_type = type(error).__name__

    # Log the error with context
    logger.error(f"Security Error [{error_type}]: {str(error)}")
    logger.error(f"Request: {request.method} {request.url}")
    logger.error(f"User Agent: {request.headers.get('User-Agent', 'Unknown')}")
    logger.error(f"IP: {request.remote_addr}")

    # Log stack trace for debugging
    logger.error(f"Traceback: {traceback.format_exc()}")

    # Return appropriate response
    if isinstance(error, ValidationError):
        return jsonify({
            'status': 'error',
            'error': 'Invalid input provided',
            'details': str(error)
        }), 400

    elif isinstance(error, ScanError):
        return jsonify({
            'status': 'error',
            'error': 'Scan operation failed',
            'details': str(error)
        }), 500

    elif isinstance(error, DatabaseError):
        return jsonify({
            'status': 'error',
            'error': 'Database operation failed',
            'details': str(error)
        }), 500

    else:
        return jsonify({
            'status': 'error',
            'error': 'Security error occurred',
            'details': str(error)
        }), 500

def log_security_event(event_type, details, user_id=None, severity='INFO'):
    """Log security events consistently."""
    log_data = {
        'event_type': event_type,
        'details': details,
        'user_id': user_id,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'url': request.url,
        'method': request.method
    }

    log_message = f"Security Event [{event_type}]: {details}"

    if severity == 'ERROR':
        logger.error(log_message, extra=log_data)
    elif severity == 'WARNING':
        logger.warning(log_message, extra=log_data)
    else:
        logger.info(log_message, extra=log_data)

def safe_database_operation(operation_name):
    """Decorator for safe database operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Database operation '{operation_name}' failed: {str(e)}")
                logger.error(f"Traceback: {traceback.format_exc()}")

                # Try to rollback if we have a session
                try:
                    from models import db
                    if db.session:
                        db.session.rollback()
                except Exception:
                    pass

                raise DatabaseError(f"Database operation '{operation_name}' failed: {str(e)}")
        return wrapper
    return decorator

def safe_scan_operation(operation_name):
    """Decorator for safe scanning operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                log_security_event('scan_start', f'Starting {operation_name}', severity='INFO')
                result = func(*args, **kwargs)
                log_security_event('scan_complete', f'Completed {operation_name}', severity='INFO')
                return result
            except Exception as e:
                log_security_event('scan_error', f'Failed {operation_name}: {str(e)}', severity='ERROR')
                raise ScanError(f"Scan operation '{operation_name}' failed: {str(e)}")
        return wrapper
    return decorator

def validate_request_data(required_fields=None, optional_fields=None):
    """Decorator to validate request data."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Get request data
                if request.is_json:
                    data = request.get_json()
                else:
                    data = request.form.to_dict()

                if data is None:
                    data = {}

                # Check required fields
                if required_fields:
                    missing_fields = []
                    for field in required_fields:
                        if field not in data or not data[field]:
                            missing_fields.append(field)

                    if missing_fields:
                        raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")

                # Validate field formats if validators provided
                if optional_fields:
                    for field, validator in optional_fields.items():
                        if field in data and data[field]:
                            try:
                                if callable(validator):
                                    data[field] = validator(data[field])
                            except Exception as e:
                                raise ValidationError(f"Invalid format for field '{field}': {str(e)}")

                # Store validated data in flask g for access in route
                g.validated_data = data

                return func(*args, **kwargs)

            except ValidationError:
                raise
            except Exception as e:
                logger.error(f"Request validation error: {str(e)}")
                raise ValidationError(f"Request validation failed: {str(e)}")
        return wrapper
    return decorator

def handle_http_error(error):
    """Handle HTTP errors consistently."""
    if isinstance(error, HTTPException):
        return jsonify({
            'status': 'error',
            'error': error.name,
            'details': error.description
        }), error.code

    return jsonify({
        'status': 'error',
        'error': 'Internal Server Error',
        'details': str(error)
    }), 500

def create_security_headers(response):
    """Add security headers to response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Enhanced CSP
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://cdnjs.cloudflare.com; "
        "connect-src 'self' ws://127.0.0.1:5000 wss://127.0.0.1:5000 ws://localhost:5000 wss://localhost:5000 https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    response.headers['Content-Security-Policy'] = csp

    return response

def rate_limit_error_handler():
    """Handle rate limiting errors."""
    return jsonify({
        'status': 'error',
        'error': 'Rate limit exceeded',
        'details': 'Too many requests. Please try again later.'
    }), 429

def setup_error_handlers(app):
    """Set up all error handlers for the Flask application."""
    app.register_error_handler(SecurityError, handle_security_error)
    app.register_error_handler(HTTPException, handle_http_error)
    app.register_error_handler(429, rate_limit_error_handler)

    # Add security headers to all responses
    @app.after_request
    def add_security_headers(response):
        return create_security_headers(response)

    logger.info("Security error handlers configured")