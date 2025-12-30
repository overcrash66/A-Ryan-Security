from flask import request, abort
from flask_login import current_user
import re
from functools import wraps
import logging
SCANNER_SIGNATURES = [
    r'nmap',
    r'nikto',
    r'gobuster',
    r'wpscan',
    r'sqlmap',
    r'dirbuster',
    r'whatweb',
    r'acunetix',
    r'burpsuite',
    r'w3af',
    r'HNAP1',
    r'sdk',
    r'nmaplowercheck',
    r'evox/about'
]

def is_scanner_request():
    """Check if the current request matches known scanner patterns."""
    user_agent = request.headers.get('User-Agent', '').lower()
    path = request.path.lower()
    
    if any(sig.lower() in user_agent for sig in SCANNER_SIGNATURES):
        return True
        
    if any(sig.lower() in path for sig in SCANNER_SIGNATURES):
        return True
        
    scan_patterns = [
        r'\.php$',
        r'\.asp$',
        r'\.jsp$',
        r'\.env$',
        r'wp-',
        r'admin',
        r'backup',
        r'\.git',
        r'\.sql$'
    ]
    
    if any(re.search(pattern, path) for pattern in scan_patterns):
        return True
    
    return False

def block_scanners(f):
    """Decorator to block known vulnerability scanners."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_scanner_request():
            from models import db, AuditLog
            from flask_login import current_user
            
            audit = AuditLog(
                user_id=current_user.id if hasattr(current_user, 'id') and current_user.is_authenticated else None,
                action='blocked_scan',
                ip_address=request.remote_addr,
                details=f'Blocked scan attempt: UA={request.headers.get("User-Agent")}, Path={request.path}'
            )
            try:
                db.session.add(audit)
                db.session.commit()
            except Exception as e:
                logging.error(f"Error logging blocked scan: {e}")
                db.session.rollback()
            
            abort(404)
        return f(*args, **kwargs)
    return decorated_function