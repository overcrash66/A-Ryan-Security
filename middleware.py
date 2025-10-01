from functools import wraps
from flask import request, abort, current_app, has_request_context, has_app_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import AuditLog, db
import logging
from flask_login import current_user
import time
import re
from cache import cache

from flask import session
import hashlib

def create_limiter(app):
    """Create rate limiter for the application using SimpleCache."""
    storage_uri = "memory://"
    
    return Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=storage_uri,
        strategy="fixed-window"
    )

def audit_log(action):
    """Enhanced decorator to create audit logs with proper context handling."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = None
            start_time = time.time()
            
            try:
                result = f(*args, **kwargs)
                status = "success"
            except Exception as e:
                logging.error(f"Function error in {action}: {str(e)}")
                status = "error"
                raise
            finally:
                try:
                    # Only create audit logs if we have proper context
                    if not has_app_context() or not has_request_context():
                        logging.warning(f"Skipping audit log for {action}: No proper Flask context")
                        return result
                    
                    # Safely prepare request details
                    request_details = {}
                    try:
                        if hasattr(request, 'is_json') and request.is_json:
                            json_data = request.get_json(silent=True) or {}
                            # Filter sensitive data
                            request_details = {k: v for k, v in json_data.items() 
                                             if k not in ['password', 'token', 'secret']}
                        elif hasattr(request, 'form') and request.form:
                            # Filter sensitive form data
                            request_details = {k: v for k, v in request.form.to_dict().items() 
                                             if k not in ['password', 'csrf_token', 'current_password', 
                                                         'new_password', 'confirm_password']}
                    except Exception as req_error:
                        logging.warning(f"Could not parse request details: {req_error}")
                        request_details = {"error": "Could not parse request"}
                    
                    # Get user ID safely
                    user_id = None
                    try:
                        if hasattr(current_user, 'id') and current_user.is_authenticated:
                            user_id = current_user.id
                    except RuntimeError as auth_error:
                        if "outside of request context" not in str(auth_error):
                            logging.warning(f"User context error: {auth_error}")
                    
                    # Calculate execution time
                    execution_time = round((time.time() - start_time) * 1000, 2)  # ms
                    
                    # Create audit log entry
                    audit = AuditLog(
                        user_id=user_id,
                        action=action,
                        ip_address=getattr(request, 'remote_addr', None),
                        user_agent=request.headers.get('User-Agent', '') if hasattr(request, 'headers') else '',
                        endpoint=getattr(request, 'endpoint', None),
                        method=getattr(request, 'method', None),
                        path=getattr(request, 'path', None),
                        status=status,
                        execution_time=execution_time,
                        details=str(request_details)[:500]  # Limit size
                    )
                    
                    db.session.add(audit)
                    db.session.commit()
                    
                except Exception as audit_error:
                    logging.error(f"Audit log error for {action}: {str(audit_error)}")
                    # Don't rollback if the original operation succeeded
                    try:
                        if db.session.is_active:
                            db.session.rollback()
                    except Exception:
                        pass
                        
            return result
        return decorated_function
    return decorator

def require_admin(f):
    """Enhanced decorator to restrict access to admin users with context checking."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for proper context first
        if not has_request_context():
            logging.error("Admin check failed: No request context")
            abort(500)
        
        try:
            if not current_user.is_authenticated:
                logging.warning("Admin check failed: User not authenticated")
                abort(401)
                
            if not hasattr(current_user, 'is_admin') or not current_user.is_admin():
                if hasattr(current_user, 'id'):
                    current_app.logger.warning(f"Non-admin user {current_user.id} attempted to access admin function")
                else:
                    current_app.logger.warning("Non-admin user attempted to access admin function")
                abort(403)
                
        except RuntimeError as e:
            if "outside of request context" in str(e):
                logging.error("Admin check failed: Outside request context")
                abort(500)
            raise
            
        return f(*args, **kwargs)
    return decorated_function

def validate_input(schema):
    """Enhanced decorator to validate input using marshmallow schemas."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_request_context():
                logging.error("Input validation failed: No request context")
                return {"errors": "No request context"}, 500
                
            try:
                if request.is_json:
                    data = request.get_json() or {}
                else:
                    data = request.form.to_dict() if request.form else {}
                    
                # Add files if present
                if hasattr(request, 'files') and request.files:
                    data['_files'] = {name: file.filename for name, file in request.files.items()}
                    
                validated_data = schema().load(data)
                # Remove the _files key if it exists before passing to function
                validated_data.pop('_files', None)
                return f(*args, **validated_data, **kwargs)
                
            except Exception as err:
                if has_app_context():
                    current_app.logger.error(f"Input validation error: {str(err)}")
                else:
                    logging.error(f"Input validation error: {str(err)}")
                return {"errors": str(err)}, 400
                
        return decorated_function
    return decorator

def block_common_scans(f):
    """Enhanced decorator to block common vulnerability scans."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not has_request_context():
            # If no request context, allow the function to proceed
            return f(*args, **kwargs)
            
        try:
            # Common scan patterns to block
            scan_paths = [
                r'^/sdk', r'^/nmaplowercheck', r'^/evox/about', r'^/HNAP1',
                r'^/wp-admin', r'^/phpmyadmin', r'^/\.env', r'^/\.git',
                r'^/console', r'^/actuator', r'^/debug', r'^/test'
            ]
            
            user_agent = request.headers.get('User-Agent', '') if hasattr(request, 'headers') else ''
            scan_agents = [
                'nmap', 'nikto', 'sqlmap', 'metasploit', 'nessus',
                'acunetix', 'appscan', 'w3af', 'zap', 'burp'
            ]
            
            # Check if path matches any scan pattern
            request_path = getattr(request, 'path', '')
            if any(re.match(pattern, request_path) for pattern in scan_paths):
                if has_app_context():
                    current_app.logger.warning(f"Blocked scan attempt to {request_path} from {request.remote_addr}")
                else:
                    logging.warning(f"Blocked scan attempt to {request_path}")
                abort(404)
                
            # Check if user agent contains scan tool identifiers
            if any(agent in user_agent.lower() for agent in scan_agents):
                if has_app_context():
                    current_app.logger.warning(f"Blocked scan tool: {user_agent} from {getattr(request, 'remote_addr', 'unknown')}")
                else:
                    logging.warning(f"Blocked scan tool: {user_agent}")
                abort(403)
                
        except Exception as e:
            logging.error(f"Error in scan blocking: {e}")
            # Don't block legitimate requests due to scan detection errors
            
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_by_user(f):
    """Enhanced decorator to apply different rate limits based on user status."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not has_app_context() or not has_request_context():
            # If no proper context, proceed without rate limiting
            return f(*args, **kwargs)
            
        try:
            limiter = current_app.extensions.get('limiter')
            if not limiter:
                # No rate limiter configured, proceed normally
                return f(*args, **kwargs)
                
            # Apply different limits based on user status
            try:
                if current_user.is_authenticated:
                    # Higher limits for authenticated users
                    limiter.limit("1000 per day, 200 per hour")(f)
                else:
                    # Lower limits for anonymous users
                    limiter.limit("100 per day, 20 per hour")(f)
            except RuntimeError as e:
                if "outside of request context" in str(e):
                    # Proceed without rate limiting if context issues
                    pass
                else:
                    raise
                    
        except Exception as e:
            logging.error(f"Rate limiting error: {e}")
            # Don't block requests due to rate limiting errors
            
        return f(*args, **kwargs)
    return decorated_function

def cache_response(timeout=300):
    """Enhanced decorator to cache responses using SimpleCache with context checking."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_request_context():
                # If no request context, just execute the function
                return f(*args, **kwargs)
                
            try:
                # Generate cache key including session-specific scan path and user ID
                scan_path = session.get('preferred_scan_path', 'default')
                path_hash = hashlib.sha256(scan_path.encode()).hexdigest()
                user_id = current_user.id if current_user.is_authenticated else 'anonymous'
                cache_key = f"{request.path}_{hash(frozenset(request.args.items()))}_{path_hash}_{user_id}"
                
                # Try to get cached response
                cached_response = cache.get(cache_key)
                if cached_response:
                    return cached_response
                    
                # Call the function if not cached
                response = f(*args, **kwargs)
                
                # Cache the response
                cache.set(cache_key, response, timeout=timeout)
                
                return response
                
            except Exception as e:
                logging.error(f"Cache error in {f.__name__}: {e}")
                # If caching fails, just execute the function normally
                return f(*args, **kwargs)
                
        return decorated_function
    return decorator

def safe_context_operation(operation_name):
    """Decorator for operations that need safe context handling."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Check if we have the necessary contexts
                if not has_app_context():
                    logging.warning(f"{operation_name}: No application context available")
                    return None
                    
                # Execute the function with proper error handling
                return f(*args, **kwargs)
                
            except RuntimeError as e:
                if "outside of request context" in str(e) or "outside of application context" in str(e):
                    logging.warning(f"{operation_name}: Context error - {str(e)}")
                    return None
                else:
                    logging.error(f"{operation_name}: Runtime error - {str(e)}")
                    raise
                    
            except Exception as e:
                logging.error(f"{operation_name}: Unexpected error - {str(e)}")
                raise
                
        return decorated_function
    return decorator