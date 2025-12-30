from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session, current_app, send_from_directory, abort, make_response
from urllib.parse import urlparse, urljoin
from cache import cache
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity
from datetime import timedelta
from security_modules.scan_protection import block_scanners
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from config import Config
from models import db, User, Log, Issue, AuditLog, ScanHistory
from middleware import create_limiter, audit_log, require_admin, validate_input, cache_response
from web_interface.auth import jwt_or_api_key_required, api_key_required, admin_required
from security_modules.antivirus import extra_antivirus_layer
from security_modules.firewall import check_firewall_status, list_rules
from security_modules.vuln_checker import scan_vulnerabilities
from security_modules.network_analyzer import scan_network, analyze_traffic
from security_modules.ai_integration import get_ai_advice, predict_threats, get_comprehensive_ai_analysis
from reports import generate_pdf_report
from security_modules.process_scanner import scan_running_processes, get_system_services, get_startup_programs
import threading
import time
import logging
import os
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import json
import pytz
from datetime import timezone
import socket
import subprocess
import re
import ipaddress
import requests
from urllib.parse import quote
from web_interface.performance_optimizer import performance_monitor, performance_cache, optimize_database_queries
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from flask import g

from logging.handlers import RotatingFileHandler

from . import socketio, login_manager, csrf, bootstrap, migrate

# Create Blueprint
bp = Blueprint('main', __name__)

# Initialize Cache (needs app bound later or use simple cache for now if not attached)
# Cache typically needs app. For now we can assume it works or we need to init it in create_app too.
# But existing code uses cache object decorator.
# Let's import cache from items_per_page or whereever?
# No, app.py initialized cache: cache = Cache(config={'CACHE_TYPE': 'simple'})
# We should move Cache to __init__.py too?
# For now, let's keep cache here but init with no app?
# Or better, move cache to __init__.py and import it.

# Let's assume we move cache to __init__.py later. For now, create it here but bind to current_app?
# Flask-Caching can be initialized with app later.
# The `cache` object is already imported from `cache.py` which is initialized in `__init__.py`.
# So, no need to re-initialize it here.

# Configure logging (moved to main.py or create_app)
# This section is commented out in the instruction, implying it's handled elsewhere.

# Initialize Flask app with security headers


# Import and initialize extensions in correct order
# Extensions are initialized in __init__.py and imported
from . import socketio, login_manager, csrf, bootstrap, migrate, limiter

# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=64)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Change password form
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=12)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

def url_is_safe(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

#new
# Add these imports at the top of app.py
from functools import partial
from flask import current_app
import threading
from contextlib import contextmanager

# Add this context manager after the imports
@contextmanager
def safe_app_context():
    """Context manager to safely handle Flask app context operations."""
    try:
        if current_app:
            yield current_app
        else:
            raise RuntimeError("No active application context")
    except RuntimeError as e:
        if "outside of application context" in str(e):
             raise RuntimeError("No active application context")
        else:
            raise
    except Exception as e:
        # Log error using print as fallback if current_app logger is unavailable 
        # (though current_app would be available if we yielded it)
        print(f"Error in safe app context: {e}")
        yield None

def safe_vulnerability_scan(scan_path=None, save_history=True):
    """Thread-safe vulnerability scanning with proper context handling."""
    try:
        # Use app context for the scan
        with safe_app_context() as context_app:
            if context_app:
                return scan_vulnerabilities(scan_path=scan_path, save_history=save_history)
            else:
                current_app.logger.warning("No app context available for vulnerability scan")
                return scan_vulnerabilities(scan_path=scan_path, save_history=False)
    except Exception as e:
        current_app.logger.error(f"Error in safe vulnerability scan: {e}")
        # Fallback to basic scan without history
        return scan_vulnerabilities(scan_path=scan_path, save_history=False)

def safe_network_analysis(count=5):
    """Thread-safe network analysis."""
    try:
        return analyze_traffic(count=count)
    except Exception as e:
        current_app.logger.error(f"Error in network analysis: {e}")
        return []

def safe_process_scan():
    """Thread-safe process scanning."""
    try:
        return scan_running_processes()
    except Exception as e:
        current_app.logger.error(f"Error in process scan: {e}")
        return {'error': str(e)}

@bp.route('/status')
@login_required
@cache_response(timeout=300)  # Reduced timeout for more frequent refreshes
def status():
    logging.info("Starting /status data collection...")
    
    data = {}
    advice = "AI analysis unavailable"
    
    # Use app context for all operations
    with safe_app_context() as context_app:
        if context_app:
            # Get preferred scan path from session
            preferred_scan_path = session.get('preferred_scan_path')
            
            # Define scan tasks
            scan_tasks = [
                (extra_antivirus_layer, 'av'),
                (check_firewall_status, 'fw'),
                (scan_network, 'net'),
                (partial(safe_network_analysis, count=5), 'traffic'),
                (safe_process_scan, 'processes'),
                (get_system_services, 'services'),
                (get_startup_programs, 'startup'),
            ]
            
            # Run tasks sequentially
            # Execute scans and cache individual results for API
            for func, key in scan_tasks:
                try:
                    result = func()
                    data[key] = result
                    # Cache individual results to speed up subsequent API calls
                    cache_key = f"{key}_status"
                    cache.set(cache_key, result, timeout=300)
                    logging.info(f"Completed scan for {key} and cached as {cache_key}")
                except Exception as e:
                    logging.error(f"Scan failed for {key}: {e}")
                    data[key] = {'error': str(e)}
            
            # Run vulnerability scans with preferred path
            try:
                vulns_data, osv_data = scan_vulnerabilities(scan_path=preferred_scan_path, save_history=True)
                data['vulns'] = vulns_data
                data['osv'] = osv_data
            except Exception as e:
                logging.error(f"Vulnerability scan failed: {e}")
                data['vulns'] = {'error': str(e)}
                data['osv'] = {'error': str(e)}
            
            # Get AI advice
            try:
                advice = get_comprehensive_ai_analysis(data) or "AI analysis unavailable"
            except Exception as e:
                logging.error(f"AI advice failed: {e}")
                advice = "AI analysis unavailable"

    logging.info("/status data collection complete")
    
    # Ensure scripts are tracked to prevent duplicates
    g.loaded_scripts = getattr(g, 'loaded_scripts', [])
    if 'status_loader' not in g.loaded_scripts:
        g.loaded_scripts.append('status_loader')
    
    return render_template('status.html', data=data, advice=advice)

@bp.route('/set_scan_path', methods=['POST'])
@login_required
def set_scan_path():
    scan_path = request.form.get('scan-path')
    if scan_path and os.path.exists(scan_path):  # Basic validation
        session['preferred_scan_path'] = scan_path
        flash('Scan folder set successfully!', 'success')
    else:
        flash('Invalid folder path.', 'error')
    return redirect(url_for('main.status'))

# Update API endpoints with proper context handling
@bp.route('/api/status/vulns')
@jwt_or_api_key_required
def api_status_vulns():
    try:
        vulns_data = cache.get('vulns_status')
        osv_data = cache.get('osv_status')
        
        if vulns_data is None or osv_data is None:
            preferred_scan_path = session.get('preferred_scan_path')
            # Use safe vulnerability scan with proper context
            # vulns_data, osv_data = safe_vulnerability_scan(
            #     scan_path=preferred_scan_path, 
            #     save_history=True
            # )
            vulns_data, osv_data = scan_vulnerabilities(scan_path=preferred_scan_path,save_history=True)
            cache.set('vulns_status', vulns_data, timeout=300)
            cache.set('osv_status', osv_data, timeout=300)
            
        return jsonify({'status': 'success', 'data': {'vulns': vulns_data, 'osv': osv_data}})
    except Exception as e:
        current_app.logger.error(f"Error getting vulnerability data: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/status/traffic')
@login_required
def api_status_traffic():
    try:
        traffic_data = cache.get('traffic_status')
        if traffic_data is None:
            traffic_data = safe_network_analysis(count=5)
            cache.set('traffic_status', traffic_data, timeout=300)
        
        return jsonify({'status': 'success', 'data': traffic_data})
    except Exception as e:
        current_app.logger.error(f"Error getting traffic data: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/status/processes')
@login_required
def api_status_processes():
    try:
        processes = cache.get('process_status')
        if processes is None:
            processes = safe_process_scan()
            cache.set('process_status', processes, timeout=300)
        
        return jsonify({'status': 'success', 'data': processes})
    except Exception as e:
        current_app.logger.error(f"Error getting process data: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/status/advice')
@login_required
def api_status_advice():
    try:
        # Use cached data when available for AI advice
        av = cache.get('av_status') or extra_antivirus_layer()
        fw = cache.get('fw_status') or check_firewall_status()
        vulns_data = cache.get('vulns_status')
        osv_data = cache.get('osv_status')
        
        if vulns_data is None or osv_data is None:
            preferred_scan_path = session.get('preferred_scan_path')
            # vulns_data, osv_data = safe_vulnerability_scan(
            #     scan_path=preferred_scan_path,
            #     save_history=False  # Don't save history for advice requests
            # )
            vulns_data, osv_data = scan_vulnerabilities(scan_path=preferred_scan_path, save_history=False)
            cache.set('vulns_status', vulns_data, timeout=300)
            cache.set('osv_status', osv_data, timeout=300)
        
        processes = cache.get('process_status') or safe_process_scan()
        net = cache.get('net_status') or scan_network()
        traffic = cache.get('traffic_status') or safe_network_analysis(count=5)
        
        all_data = {
            'av': av, 'fw': fw, 'vulns': vulns_data, 'osv': osv_data,
            'processes': processes, 'net': net, 'traffic': traffic
        }
        
        advice = get_ai_advice(all_data)
        return jsonify({'status': 'success', 'data': advice})
    except Exception as e:
        current_app.logger.error(f"Error getting AI advice: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

# Update custom scan route with proper context handling
@bp.route('/custom_scan', methods=['GET', 'POST'])
@login_required
@block_scanners
def custom_scan():
    """Custom vulnerability scan with user-selected folder and proper context handling."""
    if request.method == 'POST':
        scan_path = request.form.get('scan_path', '').strip()
        
        if not scan_path:
            flash('Please provide a valid scan path', 'error')
            preferred_scan_path = session.get('preferred_scan_path', '')
            return render_template('custom_scan.html', preferred_scan_path=preferred_scan_path)
        
        # Validate the path exists and is accessible
        if not os.path.exists(scan_path):
            flash(f'Path does not exist: {scan_path}', 'error')
            preferred_scan_path = session.get('preferred_scan_path', '')
            return render_template('custom_scan.html', preferred_scan_path=preferred_scan_path)
        
        if not os.access(scan_path, os.R_OK):
            flash(f'Cannot access path (permission denied): {scan_path}', 'error')
            preferred_scan_path = session.get('preferred_scan_path', '')
            return render_template('custom_scan.html', preferred_scan_path=preferred_scan_path)
        
        try:
            current_app.logger.info(f"Starting custom scan of {scan_path} by user {current_user.username}")
            
            # Use safe vulnerability scan with proper context
            #vulns_data, osv_data = safe_vulnerability_scan(scan_path=scan_path, save_history=True)
            vulns_data, osv_data = scan_vulnerabilities(scan_path=scan_path, save_history=True)
            # Cache the results
            cache.set('custom_vulns_status', vulns_data, timeout=300)
            cache.set('custom_osv_status', osv_data, timeout=300)
            cache.set('custom_scan_path', scan_path, timeout=300)
            
            # Save this as the user's preferred scan path for future scans
            session['preferred_scan_path'] = scan_path
            current_app.logger.info(f"Saved {scan_path} as user's preferred scan path")
            
            flash(f'Scan completed for: {scan_path}', 'success')
            return redirect(url_for('main.custom_scan_results'))
            
        except Exception as e:
            current_app.logger.error(f"Error during custom scan: {e}")
            flash(f'Error during scan: {str(e)}', 'error')
            preferred_scan_path = session.get('preferred_scan_path', '')
            return render_template('custom_scan.html', preferred_scan_path=preferred_scan_path)
    
    # GET request - show the form
    preferred_scan_path = session.get('preferred_scan_path', '')
    return render_template('custom_scan.html', preferred_scan_path=preferred_scan_path)

@csrf.exempt
@bp.route('/set_scan_folder', methods=['POST'])
@login_required
@block_scanners
def set_scan_folder():
    """Set the preferred scan folder with enhanced validation."""
    scan_path = request.form.get('scan_path', '').strip()
    
    current_app.logger.info(f"set_scan_folder called by user {current_user.username}")
    current_app.logger.info(f"Received scan_path: '{scan_path}'")
    
    if not scan_path:
        current_app.logger.warning("Empty scan path provided")
        flash('Please provide a valid scan path', 'error')
        return redirect(url_for('main.status'))
    
    # Enhanced path validation
    try:
        # Normalize the path
        normalized_path = os.path.normpath(scan_path)
        
        # Check if path exists
        if not os.path.exists(normalized_path):
            current_app.logger.warning(f"Path does not exist: {normalized_path}")
            flash(f'Path does not exist: {normalized_path}', 'error')
            return redirect(url_for('main.status'))
        
        # Check if path is accessible
        if not os.access(normalized_path, os.R_OK):
            current_app.logger.warning(f"Cannot access path: {normalized_path}")
            flash(f'Cannot access path (permission denied): {normalized_path}', 'error')
            return redirect(url_for('main.status'))
        
        # Additional security check - prevent scanning of sensitive system directories
        sensitive_paths = [
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Program Files\\WindowsApps',
            '/etc',
            '/usr/bin',
            '/bin'
        ]
        
        for sensitive_path in sensitive_paths:
            if normalized_path.lower().startswith(sensitive_path.lower()):
                current_app.logger.warning(f"Attempted to set sensitive system path: {normalized_path}")
                flash(f'Cannot scan sensitive system directory: {normalized_path}', 'warning')
                return redirect(url_for('main.status'))
        
        # Save the validated path
        session['preferred_scan_path'] = normalized_path
        current_app.logger.info(f"Successfully set preferred scan path to: {normalized_path}")
        
        # Clear cached vulnerability data to force refresh with new path
        cache.delete('vulns_status')
        cache.delete('osv_status')
        current_app.logger.info("Cleared vulnerability cache to force refresh")
        
        flash(f'Scan folder set to: {normalized_path}', 'success')
        
    except Exception as e:
        current_app.logger.error(f"Error setting scan folder: {e}")
        flash(f'Error setting scan folder: {str(e)}', 'error')
    
    return redirect(url_for('main.status'))

# Add thread cleanup function


# Enhanced error handler for context issues
@bp.app_errorhandler(RuntimeError)
def handle_runtime_error(error):
    """Handle runtime errors, especially context-related ones."""
    error_msg = str(error)
    
    if "outside of application context" in error_msg or "outside of request context" in error_msg:
        current_app.logger.error(f"Context error: {error_msg}")
        
        # Try to provide a user-friendly error page
        return render_template('error.html', error={
            'code': 500,
            'name': 'Application Context Error',
            'description': 'A context error occurred. Please refresh the page and try again.'
        }), 500
    
    # For other runtime errors, use the default handler
    return str(error)

#old
# Performance monitoring hooks
@bp.before_request
def before_request():
    performance_monitor.start_request_timer()



import mimetypes
from flask import send_from_directory

mimetypes.add_type('application/javascript', '.js')

@bp.route('/static/<path:filename>')
def custom_static(filename):
    response = send_from_directory(current_app.static_folder, filename)
    if filename.endswith('.js'):
        response.mimetype = 'application/javascript'
    return response


# Template filters for time conversion
def get_user_timezone():
    """Get user's timezone from session or default to system timezone."""
    # Try to get timezone from session (could be set by user preference)
    user_tz = session.get('user_timezone')
    if user_tz:
        try:
            return pytz.timezone(user_tz)
        except:
            pass
    
    # Default to America/Halifax (from environment details)
    return pytz.timezone('America/Halifax')

@bp.app_template_filter('local_datetime')
def local_datetime_filter(utc_dt):
    """Convert UTC datetime to local datetime for display."""
    if utc_dt is None:
        return 'N/A'
    
    # If the datetime is naive (no timezone info), assume it's UTC
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    
    # Convert to user's local timezone
    local_tz = get_user_timezone()
    local_dt = utc_dt.astimezone(local_tz)
    
    return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z')

@bp.app_template_filter('local_date')
def local_date_filter(utc_dt):
    """Convert UTC datetime to local date for display."""
    if utc_dt is None:
        return 'N/A'
    
    # If the datetime is naive (no timezone info), assume it's UTC
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    
    # Convert to user's local timezone
    local_tz = get_user_timezone()
    local_dt = utc_dt.astimezone(local_tz)
    
    return local_dt.strftime('%Y-%m-%d %H:%M')

@bp.app_template_filter('current_time')
def current_time_filter(dummy=None):
    """Get current local time for display."""
    local_tz = get_user_timezone()
    current_time = datetime.now(local_tz)
    return current_time.strftime('%Y-%m-%d %H:%M:%S %Z')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# API Authentication endpoints
@bp.route('/api/auth/login', methods=['POST'])
def api_login():
    """Login endpoint for API access."""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"msg": "Missing username or password"}), 400
        
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        # Update last login time
        user.last_login = datetime.now(timezone.utc)
        
        # Generate tokens 
        access_token = create_access_token(
            identity=str(user.id),  # Convert id to string for JWT
            additional_claims={'role': user.role}
        )
        
        # Log the successful login
        log = AuditLog(
            user_id=user.id,
            action='api_login',
            details='API login successful',
            ip_address=request.remote_addr
        )
        
        try:
            db.session.add(log)
            db.session.commit()
        except:
            db.session.rollback()
            # Continue even if logging fails
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,  # 1 hour
            'user_id': user.id,
            'role': user.role
        })
    
    # Log failed login attempt
    try:
        log = AuditLog(
            action='api_login_failed',
            details=f'Failed login attempt for user: {data.get("username")}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except:
        db.session.rollback()
    
    return jsonify({"msg": "Invalid username or password"}), 401

@bp.route('/api/auth/token', methods=['POST'])
@jwt_or_api_key_required
def generate_api_key():
    """Generate or regenerate API key."""
    # Get the current user from JWT or API key
    user_id = get_jwt_identity()
    user = User.query.get(user_id) if user_id else None
    
    if not user:
        api_key = request.headers.get('X-API-Key')
        if api_key:
            user = User.query.filter_by(api_key=api_key).first()
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    # Generate new API key
    api_key = user.generate_api_key()
    
    # Log key generation
    log = AuditLog(
        user_id=user.id,
        action='api_key_generated',
        details='New API key generated',
        ip_address=request.remote_addr
    )
    
    try:
        db.session.add(log)
        db.session.commit()
    except:
        db.session.rollback()
        return jsonify({"msg": "Error generating API key"}), 500
    
    return jsonify({
        "api_key": api_key,
        "expires_at": user.api_key_expires_at.isoformat() if user.api_key_expires_at else None
    })

@bp.route('/login', methods=['GET', 'POST'])
@block_scanners
def login():
    current_app.logger.debug(f"Accessing /login route, method: {request.method}")
    form = LoginForm()
    if form.validate_on_submit():
        current_app.logger.debug(f"Login form validated for username: {form.username.data}")
        username = form.username.data.strip()
        password = form.password.data
        
        if not username or not password:
            flash('Please provide both username and password', 'error')
            current_app.logger.warning("Login failed: Missing username or password")
            return render_template('login.html', form=form), 400
            
        user = User.query.filter_by(username=username).first()
        if not user:
            current_app.logger.error(f"No user found for username: {username}")
        
        # Get failed attempts from cache
        failed_attempts = cache.get(f'login_attempts_{username}') or 0
        
        if failed_attempts >= 5:
            flash('Account temporarily locked. Please try again later or contact support.', 'error')
            current_app.logger.warning(f"Account locked for {username}: Too many failed attempts")
            return render_template('login.html', form=form), 429
            
        if user and user.check_password(password):
            # Reset failed attempts on successful login
            cache.delete(f'login_attempts_{username}')
            
            # Check if password change required
            if user.password_change_required:
                flash('Your password must be changed before proceeding.', 'warning')
                current_app.logger.info(f"Redirecting {username} to change_password")
                return redirect(url_for('main.change_password'))
            
            login_user(user, duration=timedelta(hours=1))
            current_app.logger.info(f"Successful login for {username}, session: {session}")
            
            next_page = request.args.get('next')
            if next_page:
                current_app.logger.info(f"Redirecting to {next_page}, Safe: {url_is_safe(next_page)}")
            if next_page and url_is_safe(next_page):
                return redirect(next_page)
            current_app.logger.debug("Redirecting to index")
            return redirect(url_for('main.index'))
        else:
            failed_attempts += 1
            cache.set(f'login_attempts_{username}', failed_attempts, timeout=300)
            flash('Invalid username or password', 'error')
            current_app.logger.info(f"Failed login for {username}: incorrect password or user not found")
            return render_template('login.html', form=form)
    elif request.method == 'POST':
        current_app.logger.warning(f"Login form validation failed: {form.errors}")
        flash('Invalid form submission. Please check your input.', 'error')
    
    current_app.logger.debug("Rendering login.html for GET request")
    return render_template('login.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.index'))

@bp.route('/change_password', methods=['GET', 'POST'])
@block_scanners
@login_required
def change_password():
    current_app.logger.debug("Accessing /change_password route")
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_app.logger.debug("Change password form validated")
        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data
        
        # Enhanced logging for debugging
        current_app.logger.info(f"Password change attempt by user: {current_user.username}")
        current_app.logger.debug(f"Current password length: {len(current_password)}")
        current_app.logger.debug(f"New password length: {len(new_password)}")
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            current_app.logger.warning("Change password failed: Passwords do not match")
            return render_template('change_password.html', form=form), 400
            
        user = current_user
        
        # CRITICAL FIX: Check if current password verification fails
        if not user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            current_app.logger.warning(f"Change password failed: Incorrect current password for user {user.username}")
            return render_template('change_password.html', form=form), 400
        
        current_app.logger.info(f"Current password verified successfully for user {user.username}")
        
        # Check if new password is same as current (prevent reuse)
        if user.check_password(new_password):
            flash('New password must be different from current password', 'error')
            current_app.logger.warning("Change password failed: New password same as current")
            return render_template('change_password.html', form=form), 400
        
        # Validate password complexity
        if len(new_password) < 12:
            flash('Password must be at least 12 characters long', 'error')
            current_app.logger.warning(f"Change password failed: Password too short ({len(new_password)} chars)")
            return render_template('change_password.html', form=form), 400
        
        # Additional complexity checks
        has_upper = any(c.isupper() for c in new_password)
        has_lower = any(c.islower() for c in new_password)
        has_digit = any(c.isdigit() for c in new_password)
        has_special = any(c in "!@#$%^&*" for c in new_password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            flash('Password must contain uppercase, lowercase, digit, and special character (!@#$%^&*)', 'error')
            current_app.logger.warning("Change password failed: Password complexity requirements not met")
            return render_template('change_password.html', form=form), 400
            
        try:
            current_app.logger.info(f"Attempting to set new password for user {user.username}")
            user.set_password(new_password)
            user.password_change_required = False
            user.last_password_change = datetime.utcnow()
            user.password_expires = datetime.utcnow() + timedelta(days=90)
            
            audit = AuditLog(
                user_id=user.id,
                action='password_change',
                ip_address=request.remote_addr,
                details='Password changed successfully'
            )
            db.session.add(audit)
            
            # Commit the transaction
            db.session.commit()
            current_app.logger.info(f"Password change transaction committed successfully for user {user.username}")
            
            flash('Password changed successfully', 'success')
            return redirect(url_for('main.index'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error changing password for user {user.username}: {e}")
            flash('Internal error during password change. Please try again.', 'error')
            return render_template('change_password.html', form=form), 500
    elif request.method == 'POST':
        current_app.logger.warning(f"Change password form validation failed: {form.errors}")
        flash('Invalid form submission. Please check your input.', 'error')
    
    current_app.logger.debug("Rendering change_password.html for GET request")
    return render_template('change_password.html', form=form)

@bp.route('/')
@block_scanners
@login_required
def index():
    current_app.logger.debug("Accessing /index route")
    if current_user.password_change_required and request.path != url_for('main.change_password'):
        flash('Please change your password', 'warning')
        current_app.logger.info(f"Redirecting {current_user.username} to change_password from index")
        return redirect(url_for('main.change_password'))
    current_app.logger.debug("Rendering index.html")
    return render_template('index.html')

def create_system_logs(data):
    """Create system log entries based on scan results for AI analysis."""
    try:
        from models import Log
        
        # Log vulnerability scan results
        if data.get('vulns'):
            total_vulns = sum(data['vulns'].values()) if isinstance(data['vulns'], dict) else 0
            if total_vulns > 0:
                log_entry = Log(
                    level='WARNING',
                    message=f'Vulnerability scan detected {total_vulns} vulnerabilities across {len(data["vulns"])} packages',
                    user_id=current_user.id if current_user.is_authenticated else None,
                    ip_address=request.remote_addr,
                    event_type='vulnerability_scan'
                )
                db.session.add(log_entry)
        
        # Log OSV scan results with critical vulnerabilities
        if data.get('osv', {}).get('raw_output'):
            raw_output = data['osv']['raw_output']
            if 'Critical' in raw_output:
                log_entry = Log(
                    level='ERROR',
                    message='Critical vulnerabilities detected in OSV scan - immediate attention required',
                    user_id=current_user.id if current_user.is_authenticated else None,
                    ip_address=request.remote_addr,
                    event_type='critical_vulnerability'
                )
                db.session.add(log_entry)
            elif 'High' in raw_output:
                log_entry = Log(
                    level='WARNING',
                    message='High severity vulnerabilities detected in OSV scan',
                    user_id=current_user.id if current_user.is_authenticated else None,
                    ip_address=request.remote_addr,
                    event_type='high_vulnerability'
                )
                db.session.add(log_entry)
        
        # Log antivirus status
        if data.get('av') and 'error' in str(data['av']).lower():
            log_entry = Log(
                level='WARNING',
                message=f'Antivirus scan issue: {data["av"]}',
                user_id=current_user.id if current_user.is_authenticated else None,
                ip_address=request.remote_addr,
                event_type='antivirus_issue'
            )
            db.session.add(log_entry)
        
        # Log firewall status
        if data.get('fw') and 'error' in str(data['fw']).lower():
            log_entry = Log(
                level='WARNING',
                message=f'Firewall status issue: {data["fw"]}',
                user_id=current_user.id if current_user.is_authenticated else None,
                ip_address=request.remote_addr,
                event_type='firewall_issue'
            )
            db.session.add(log_entry)
        
        # Log network security issues
        if data.get('net') and 'error' in str(data['net']).lower():
            log_entry = Log(
                level='INFO',
                message=f'Network scan completed: {data["net"]}',
                user_id=current_user.id if current_user.is_authenticated else None,
                ip_address=request.remote_addr,
                event_type='network_scan'
            )
            db.session.add(log_entry)
        
        # Commit all log entries
        db.session.commit()
        current_app.logger.info("DEBUG: Created system log entries for AI analysis")
        
    except Exception as e:
        current_app.logger.error(f"Error creating system logs: {e}")
        db.session.rollback()

# API endpoints for async status loading
@bp.route('/api/status/av')

@jwt_or_api_key_required
def api_status_av():
    try:
        av_data = cache.get('av_status') or extra_antivirus_layer()
        cache.set('av_status', av_data, timeout=300)
        return jsonify({'status': 'success', 'data': av_data})
    except Exception as e:
        current_app.logger.error(f"Error getting AV status: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/status/fw')

@jwt_or_api_key_required
def api_status_fw():
    try:
        fw_data = cache.get('fw_status') or check_firewall_status()
        cache.set('fw_status', fw_data, timeout=300)
        return jsonify({'status': 'success', 'data': fw_data})
    except Exception as e:
        current_app.logger.error(f"Error getting firewall status: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500


@bp.route('/api/status/net')

@jwt_or_api_key_required
def api_status_net():
    try:
        net_data = cache.get('net_status') or scan_network()
        cache.set('net_status', net_data, timeout=300)
        return jsonify({'status': 'success', 'data': net_data})
    except Exception as e:
        current_app.logger.error(f"Error getting network data: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/history/logs')
@login_required
def api_history_logs():
    try:
        logs = Log.query.order_by(Log.timestamp.desc()).limit(20).all()
        logs_data = [{
            'id': log.id,
            'level': log.level,
            'message': log.message,
            'timestamp': log.timestamp.isoformat() if log.timestamp else None,
            'user_id': log.user_id,
            'ip_address': log.ip_address,
            'event_type': log.event_type
        } for log in logs]
        return jsonify({'status': 'success', 'data': logs_data})
    except Exception as e:
        current_app.logger.error(f"Error getting logs: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/history/issues')
@login_required
def api_history_issues():
    try:
        issues = Issue.query.order_by(Issue.severity.desc()).all()
        issues_data = [{
            'id': issue.id,
            'category': issue.category,
            'description': issue.description,
            'severity': issue.severity,
            'resolved': issue.resolved,
        } for issue in issues]
        return jsonify({'status': 'success', 'data': issues_data})
    except Exception as e:
        current_app.logger.error(f"Error getting issues: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/history/predictions')
@login_required
def api_history_predictions():
    try:
        logs = Log.query.order_by(Log.timestamp.desc()).limit(20).all()
        if logs:
            log_messages = [log.message for log in logs if log.message]
            if log_messages:
                predictions = predict_threats(log_messages)
            else:
                predictions = "No log messages available for analysis."
        else:
            predictions = "No logs available for analysis."
        return jsonify({'status': 'success', 'data': predictions})
    except Exception as e:
        current_app.logger.error(f"Error getting predictions: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/history/scan_history')
@login_required
def api_history_scan_history():
    try:
        scan_history = []
        if current_user.is_authenticated:
            scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).limit(20).all()
            scan_history = [{
                'id': scan.id,
                'scan_path': scan.scan_path,
                'status': scan.status,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'scan_duration': scan.scan_duration,
                'osv_version': scan.osv_version,
                'timestamp': scan.timestamp.isoformat() if scan.timestamp else None
            } for scan in scans]
        return jsonify({'status': 'success', 'data': scan_history})
    except Exception as e:
        current_app.logger.error(f"Error getting scan history: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/status/batch')
@login_required
def api_status_batch():
    """Batch API endpoint to get all status data in one request for better performance."""
    try:
        current_app.logger.info("Batch status API called - optimized performance")
        
        # Get all cached data first
        av = cache.get('av_status')
        fw = cache.get('fw_status')
        vulns_data = cache.get('vulns_status')
        osv_data = cache.get('osv_status')
        net = cache.get('net_status')
        traffic = cache.get('traffic_status')
        processes = cache.get('process_status')
        advice = cache.get('ai_advice')
        
        # Only run expensive operations if absolutely necessary
        if av is None:
            av = extra_antivirus_layer()
            cache.set('av_status', av, timeout=600)
        
        if fw is None:
            fw = check_firewall_status()
            cache.set('fw_status', fw, timeout=600)
        
        if net is None:
            net = scan_network()
            cache.set('net_status', net, timeout=300)
        
        if traffic is None:
            traffic = analyze_traffic(count=5)
            cache.set('traffic_status', traffic, timeout=300)
        
        # Skip expensive scans - these will be loaded separately
        if vulns_data is None:
            vulns_data = {"message": "Vulnerability scan will load separately"}
        if osv_data is None:
            osv_data = {"message": "OSV scan will load separately"}
        if processes is None:
            processes = {"message": "Process scan will load separately"}
        if advice is None:
            advice = "AI recommendations will load separately"
        
        batch_data = {
            'av': av,
            'fw': fw,
            'vulns': vulns_data,
            'osv': osv_data,
            'net': net,
            'traffic': traffic,
            'processes': processes,
            'advice': advice
        }
        
        return jsonify({'status': 'success', 'data': batch_data})
        
    except Exception as e:
        current_app.logger.error(f"Error in batch status API: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/history/batch')
@login_required
def api_history_batch():
    """Batch API endpoint to get all history data in one request."""
    try:
        current_app.logger.info("Batch history API called - optimized performance")
        
        # Get cached data first
        logs = cache.get('history_logs')
        issues = cache.get('history_issues')
        predictions = cache.get('history_predictions')
        scan_history = cache.get(f'scan_history_{current_user.id}')
        
        # Only query database if cache is empty
        if logs is None:
            logs = Log.query.order_by(Log.timestamp.desc()).limit(20).all()
            logs_data = [{
                'id': log.id,
                'level': log.level,
                'message': log.message,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'user_id': log.user_id,
                'ip_address': log.ip_address,
                'event_type': log.event_type
            } for log in logs]
            cache.set('history_logs', logs_data, timeout=300)
        else:
            logs_data = logs
        
        if issues is None:
            issues = Issue.query.order_by(Issue.severity.desc()).all()
            issues_data = [{
                'id': issue.id,
                'category': issue.category,
                'description': issue.description,
                'severity': issue.severity,
                'resolved': issue.resolved,
            } for issue in issues]
            cache.set('history_issues', issues_data, timeout=600)
        else:
            issues_data = issues
        
        # Skip expensive AI predictions initially
        if predictions is None:
            #predictions = "AI predictions will load separately"
            if logs:
                predictions = predict_threats(logs)
            else:
                predictions = "No log messages available for analysis."
        
        if scan_history is None and current_user.is_authenticated:
            scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).limit(20).all()
            scan_history_data = [{
                'id': scan.id,
                'scan_path': scan.scan_path,
                'status': scan.status,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'scan_duration': scan.scan_duration,
                'osv_version': scan.osv_version,
                'timestamp': scan.timestamp.isoformat() if scan.timestamp else None
            } for scan in scans]
            cache.set(f'scan_history_{current_user.id}', scan_history_data, timeout=300)
        else:
            scan_history_data = scan_history or []
        
        batch_data = {
            'logs': logs_data,
            'issues': issues_data,
            'predictions': predictions,
            'scan_history': scan_history_data
        }
        
        return jsonify({'status': 'success', 'data': batch_data})
        
    except Exception as e:
        current_app.logger.error(f"Error in batch history API: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/history')
@block_scanners
@login_required
@performance_cache(timeout=120)  # Cache history page for 2 minutes
def history():
    current_app.logger.debug("Accessing /history route")
    
    # Use cached data for better performance
    logs = cache.get('history_logs')
    issues = cache.get('history_issues')
    predictions = cache.get('history_predictions')
    scan_history = cache.get(f'scan_history_{current_user.id}')
    
    # Only query database if cache is empty
    if logs is None:
        logs = Log.query.order_by(Log.timestamp.desc()).limit(20).all()
        cache.set('history_logs', logs, timeout=300)  # Cache for 5 minutes
    
    if issues is None:
        issues = Issue.query.order_by(Issue.severity.desc()).limit(20).all()
        cache.set('history_issues', issues, timeout=600)  # Cache for 10 minutes
    
    # Skip expensive AI predictions on initial load - load via API
    if predictions is None:
        #predictions = "comming soon: AI predictions not available in this view"
        if logs:
            predictions = predict_threats(logs)
        else:
            predictions = "No log messages available for analysis."    
    
    # Get scan history for the current user
    if scan_history is None and current_user.is_authenticated:
        scan_history = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).limit(20).all()
        cache.set(f'scan_history_{current_user.id}', scan_history, timeout=240000)
    
    current_app.logger.debug("Rendering history.html")
    return render_template('history.html', logs=logs or [], issues=issues or [], predictions=predictions, scan_history=scan_history or [])
    #return render_template('history.html')

@bp.route('/report')
@login_required
def report():
    current_app.logger.debug("Accessing /report route")
    
    # Get current data for the report
    av = cache.get('av_status') or extra_antivirus_layer()
    fw = cache.get('fw_status') or check_firewall_status()
    vulns_data = cache.get('vulns_status')
    osv_data = cache.get('osv_status')
    
    if vulns_data is None or osv_data is None:
        # Check if user has set a preferred scan path
        preferred_scan_path = session.get('preferred_scan_path')
        if preferred_scan_path:
            current_app.logger.info(f"DEBUG: Report using user's preferred scan path: {preferred_scan_path}")
            vulns_data, osv_data = scan_vulnerabilities(scan_path=preferred_scan_path)
        else:
            current_app.logger.warning("DEBUG: /report route using default scan path (consider setting preferred path)")
            vulns_data, osv_data = scan_vulnerabilities()
    
    net = cache.get('net_status') or scan_network()
    traffic = cache.get('traffic_status') or analyze_traffic(count=5)
    
    # Include process data in reports
    processes = cache.get('process_status') or scan_running_processes()
    
    data = {
        'av': av,
        'fw': fw,
        'vulns': vulns_data,
        'osv': osv_data,
        'net': net,
        'traffic': traffic,
        'processes': processes
    }
    
    filename = generate_pdf_report(data)
    if filename:
        current_app.logger.debug(f"Rendering report.html with filename: {filename}")
        return render_template('report.html', filename=filename)
    else:
        flash('Error generating report. Please try again later.', 'error')
        current_app.logger.error("Failed to generate report")
        return redirect(url_for('main.index'))

@bp.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_users():
    """Get all users (admin only)."""
    try:
        users = User.query.all()
        return jsonify({
            'status': 'success',
            'data': [{
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'is_active': user.is_active,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'has_api_key': bool(user.api_key),
                'api_key_expires_at': user.api_key_expires_at.isoformat() if user.api_key_expires_at else None
            } for user in users]
        })
    except Exception as e:
        current_current_app.logger.error(f"Error getting users list: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def api_admin_update_user(user_id):
    """Update user details (admin only)."""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"msg": "User not found"}), 404
            
        data = request.get_json()
        if not data:
            return jsonify({"msg": "No data provided"}), 400
            
        # Update allowed fields
        if 'is_active' in data:
            user.is_active = bool(data['is_active'])
        if 'role' in data:
            user.role = data['role']
        if 'password_change_required' in data:
            user.password_change_required = bool(data['password_change_required'])
            
        # Log the changes
        log = AuditLog(
            user_id=get_jwt_identity(),
            action='user_update',
            resource_type='user',
            resource_id=user.id,
            details=f'User {user.username} updated by admin',
            ip_address=request.remote_addr
        )
        
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            "msg": "User updated successfully",
            "user": {
                "id": user.id,
                "username": user.username,
                "is_active": user.is_active,
                "role": user.role
            }
        })
    except Exception as e:
        db.session.rollback()
        current_current_app.logger.error(f"Error updating user: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/admin')
@login_required
@require_admin
def admin():
    """Admin access route for testing."""
    if not current_user.is_admin():
        return render_template('error.html', error={
            'code': 403,
            'name': 'Forbidden',
            'description': 'Admin access required'
        }), 403
    return render_template('index.html')

@bp.route('/issues', methods=['GET', 'POST'])
@login_required
def issues():
    """Issues management route for testing."""
    if request.method == 'POST':
        category = request.form.get('category')
        description = request.form.get('description')
        severity = request.form.get('severity')
        
        if category and description and severity:
            issue = Issue(
                category=category,
                description=description,
                severity=severity,
                assigned_to=current_user.id
            )
            db.session.add(issue)
            
            # Create audit log
            audit = AuditLog(
                user_id=current_user.id,
                action='issue_creation',
                resource_type='issue',
                details=f'Created issue: {description}',
                ip_address=request.remote_addr
            )
            db.session.add(audit)
            
            try:
                db.session.commit()
                flash('Issue created successfully', 'success')
                return redirect(url_for('main.issues'))
            except Exception as e:
                db.session.rollback()
                flash('Error creating issue', 'error')
                return render_template('index.html'), 500
        else:
            flash('All fields are required', 'error')
            return render_template('index.html'), 400
    
    issues = Issue.query.all()
    return render_template('index.html')

@bp.route('/custom_scan_results')
@login_required
@block_scanners
def custom_scan_results():
    """Display results of custom vulnerability scan."""
    vulns_data = cache.get('custom_vulns_status')
    osv_data = cache.get('custom_osv_status')
    scan_path = cache.get('custom_scan_path')
    
    if vulns_data is None or osv_data is None:
        flash('No scan results available. Please run a scan first.', 'warning')
        return redirect(url_for('main.custom_scan'))
    
    data = {
        'vulns': vulns_data,
        'osv': osv_data,
        'scan_path': scan_path
    }
    
    return render_template('custom_scan_results.html', data=data)

@bp.route('/clear_preferred_path', methods=['POST'])
@login_required
def clear_preferred_path():
    """Clear the user's preferred scan path."""
    if 'preferred_scan_path' in session:
        old_path = session['preferred_scan_path']
        del session['preferred_scan_path']
        current_app.logger.info(f"Cleared preferred scan path: {old_path}")
        
        # Clear cached vulnerability data to force refresh with default path
        cache.delete('vulns_status')
        cache.delete('osv_status')
        
        flash('Preferred scan path cleared. Future scans will use default path.', 'info')
    else:
        flash('No preferred scan path was set.', 'info')
    return redirect(url_for('main.status'))

@bp.route('/debug/vuln_scan')
@login_required
def debug_vuln_scan():
    """Debug route to test vulnerability scanning."""
    current_app.logger.info("DEBUG: Manual vulnerability scan test initiated")
    
    # Test with current directory (should be accessible)
    test_path = os.getcwd()
    current_app.logger.info(f"DEBUG: Testing scan with accessible path: {test_path}")
    
    try:
        vulns_data, osv_data = scan_vulnerabilities(scan_path=test_path)
        
        debug_info = {
            'test_path': test_path,
            'vulns_data': vulns_data,
            'osv_data': osv_data,
            'vulns_type': type(vulns_data).__name__,
            'osv_type': type(osv_data).__name__,
            'vulns_empty': len(vulns_data) == 0 if isinstance(vulns_data, dict) else True,
            'osv_has_error': 'error' in osv_data if isinstance(osv_data, dict) else False,
            'osv_error': osv_data.get('error') if isinstance(osv_data, dict) and 'error' in osv_data else None
        }
        
        current_app.logger.info(f"DEBUG: Scan test results: {debug_info}")
        return jsonify(debug_info)
        
    except Exception as e:
        error_info = {
            'error': str(e),
            'test_path': test_path,
            'exception_type': type(e).__name__
        }
        current_app.logger.error(f"DEBUG: Scan test failed: {error_info}")
        return jsonify(error_info), 500

@bp.route('/process_scan')
@login_required
@block_scanners
def process_scan():
    """Display detailed process scan results."""
    current_app.logger.info("Accessing /process_scan route")
    
    # Get fresh process scan data
    processes = scan_running_processes()
    
    # Get system services data
    services = get_system_services()
    
    # Get startup programs data
    startup = get_startup_programs()
    
    # Cache the results
    cache.set('process_status', processes, timeout=300)
    cache.set('services_status', services, timeout=600)  # Cache services for 10 minutes
    cache.set('startup_status', startup, timeout=1800)   # Cache startup programs for 30 minutes
    
    data = {
        'processes': processes,
        'services': services if not services.get('error') else {'error': services.get('error')},
        'startup': startup if not startup.get('error') else {'error': startup.get('error')},
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return render_template('process_scan.html', data=data)

@bp.route('/api/process_refresh', methods=['POST'])
@login_required
def api_process_refresh():
    """API endpoint to refresh process scan data."""
    try:
        current_app.logger.info("Refreshing process scan data via API")
        
        # Clear cached data
        cache.delete('process_status')
        cache.delete('services_status')
        cache.delete('startup_status')
        
        # Get fresh data
        processes = scan_running_processes()
        services = get_system_services()
        startup = get_startup_programs()
        
        # Cache the new data
        cache.set('process_status', processes, timeout=300)
        cache.set('services_status', services, timeout=600)
        cache.set('startup_status', startup, timeout=1800)
        
        return jsonify({
            'status': 'success',
            'message': 'Process scan data refreshed',
            'total_processes': processes.get('total_processes', 0),
            'suspicious_processes': processes.get('suspicious_processes', 0),
            'scan_time': processes.get('scan_time', 'Unknown')
        })
        
    except Exception as e:
        current_app.logger.error(f"Error refreshing process data: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to refresh process data: {str(e)}'
        }), 500

def perform_whois_lookup(ip_address):
    """Perform enhanced whois lookup for an IP address using multiple sources."""
    try:
        # Validate IP address
        ip_obj = ipaddress.ip_address(ip_address)
        
        # Try multiple whois APIs for comprehensive data
        whois_data = get_comprehensive_whois(ip_address)
        if whois_data and whois_data.get('status') == 'success':
            return whois_data
        
        # Fallback to traditional whois command
        traditional_data = get_traditional_whois(ip_address)
        if traditional_data and traditional_data.get('status') == 'success':
            return traditional_data
        
        # Final fallback to basic network info
        return get_basic_network_info(ip_address, ip_obj)
        
    except ValueError:
        return {'error': 'Invalid IP address format'}
    except Exception as e:
        return {'error': f'Lookup failed: {str(e)}'}

def get_comprehensive_whois(ip_address):
    """Get comprehensive whois information using multiple API sources."""
    try:
        # Try multiple whois APIs in order of preference
        
        # 1. Try ipapi.co (free, comprehensive)
        ipapi_data = get_ipapi_whois(ip_address)
        if ipapi_data and ipapi_data.get('status') == 'success':
            return ipapi_data
        
        # 2. Try ip-api.com (free, good coverage)
        ipapi_com_data = get_ipapi_com_whois(ip_address)
        if ipapi_com_data and ipapi_com_data.get('status') == 'success':
            return ipapi_com_data
        
        # 3. Try ipinfo.io (free tier available)
        ipinfo_data = get_ipinfo_whois(ip_address)
        if ipinfo_data and ipinfo_data.get('status') == 'success':
            return ipinfo_data
            
    except Exception as e:
        current_app.logger.error(f"Error in comprehensive whois lookup for {ip_address}: {e}")
    
    return None

def get_ipapi_whois(ip_address):
    """Get whois information from ipapi.co."""
    try:
        url = f"https://ipapi.co/{ip_address}/json/"
        headers = {
            'User-Agent': 'ESL-Pro-Security-Scanner/1.0'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data.get('error'):
            return None
        
        # Get hostname
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            hostname = data.get('hostname', 'Unknown')
        
        # IP address properties
        ip_obj = ipaddress.ip_address(ip_address)
        
        return {
            'ip': ip_address,
            'hostname': hostname,
            'organization': data.get('org', 'Unknown'),
            'country': data.get('country_name', 'Unknown'),
            'country_code': data.get('country_code', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'region': data.get('region', 'Unknown'),
            'isp': data.get('org', 'Unknown'),
            'asn': data.get('asn', 'Unknown'),
            'timezone': data.get('timezone', 'Unknown'),
            'postal': data.get('postal', 'Unknown'),
            'latitude': data.get('latitude', 'Unknown'),
            'longitude': data.get('longitude', 'Unknown'),
            'is_private': ip_obj.is_private,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
            'is_loopback': ip_obj.is_loopback,
            'version': ip_obj.version,
            'whois_data': f"Comprehensive IP information retrieved from ipapi.co for {ip_address}",
            'source': 'ipapi.co',
            'status': 'success'
        }
        
    except requests.RequestException as e:
        current_app.logger.warning(f"ipapi.co lookup failed for {ip_address}: {e}")
    except Exception as e:
        current_app.logger.error(f"Error in ipapi.co lookup for {ip_address}: {e}")
    
    return None

def get_ipapi_com_whois(ip_address):
    """Get whois information from ip-api.com."""
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        headers = {
            'User-Agent': 'ESL-Pro-Security-Scanner/1.0'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data.get('status') != 'success':
            return None
        
        # Get hostname
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            hostname = "Unknown"
        
        # IP address properties
        ip_obj = ipaddress.ip_address(ip_address)
        
        return {
            'ip': ip_address,
            'hostname': hostname,
            'organization': data.get('org', 'Unknown'),
            'country': data.get('country', 'Unknown'),
            'country_code': data.get('countryCode', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'region': data.get('regionName', 'Unknown'),
            'isp': data.get('isp', 'Unknown'),
            'asn': data.get('as', 'Unknown'),
            'timezone': data.get('timezone', 'Unknown'),
            'postal': data.get('zip', 'Unknown'),
            'latitude': data.get('lat', 'Unknown'),
            'longitude': data.get('lon', 'Unknown'),
            'is_private': ip_obj.is_private,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
            'is_loopback': ip_obj.is_loopback,
            'version': ip_obj.version,
            'whois_data': f"Comprehensive IP information retrieved from ip-api.com for {ip_address}",
            'source': 'ip-api.com',
            'status': 'success'
        }
        
    except requests.RequestException as e:
        current_app.logger.warning(f"ip-api.com lookup failed for {ip_address}: {e}")
    except Exception as e:
        current_app.logger.error(f"Error in ip-api.com lookup for {ip_address}: {e}")
    
    return None

def get_ipinfo_whois(ip_address):
    """Get whois information from ipinfo.io."""
    try:
        url = f"https://ipinfo.io/{ip_address}/json"
        headers = {
            'User-Agent': 'ESL-Pro-Security-Scanner/1.0'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if 'error' in data:
            return None
        
        # Get hostname
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            hostname = data.get('hostname', 'Unknown')
        
        # Parse location
        location_parts = data.get('loc', '').split(',')
        latitude = location_parts[0] if len(location_parts) > 0 else 'Unknown'
        longitude = location_parts[1] if len(location_parts) > 1 else 'Unknown'
        
        # IP address properties
        ip_obj = ipaddress.ip_address(ip_address)
        
        return {
            'ip': ip_address,
            'hostname': hostname,
            'organization': data.get('org', 'Unknown'),
            'country': data.get('country', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'region': data.get('region', 'Unknown'),
            'isp': data.get('org', 'Unknown'),
            'asn': data.get('org', 'Unknown'),
            'timezone': data.get('timezone', 'Unknown'),
            'postal': data.get('postal', 'Unknown'),
            'latitude': latitude,
            'longitude': longitude,
            'is_private': ip_obj.is_private,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
            'is_loopback': ip_obj.is_loopback,
            'version': ip_obj.version,
            'whois_data': f"Comprehensive IP information retrieved from ipinfo.io for {ip_address}",
            'source': 'ipinfo.io',
            'status': 'success'
        }
        
    except requests.RequestException as e:
        current_app.logger.warning(f"ipinfo.io lookup failed for {ip_address}: {e}")
    except Exception as e:
        current_app.logger.error(f"Error in ipinfo.io lookup for {ip_address}: {e}")
    
    return None

def get_traditional_whois(ip_address):
    """Get whois information using traditional whois command."""
    try:
        result = subprocess.run(['whois', ip_address],
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout:
            return parse_whois_output(result.stdout, ip_address)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None

def get_basic_network_info(ip_address, ip_obj):
    """Get basic network information as fallback."""
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        hostname = "Unknown"
    
    return {
        'ip': ip_address,
        'hostname': hostname,
        'is_private': ip_obj.is_private,
        'is_multicast': ip_obj.is_multicast,
        'is_reserved': ip_obj.is_reserved,
        'is_loopback': ip_obj.is_loopback,
        'version': ip_obj.version,
        'whois_data': "Limited information available - whois services unavailable",
        'organization': "Unknown",
        'country': "Unknown",
        'city': "Unknown",
        'isp': "Unknown",
        'asn': "Unknown",
        'source': 'Basic Network Info',
        'status': 'limited_info'
    }

def parse_whois_output(whois_text, ip_address):
    """Parse whois command output."""
    try:
        lines = whois_text.split('\n')
        
        # Extract key information
        org_pattern = r'(?i)(org|organization|orgname):\s*(.+)'
        country_pattern = r'(?i)(country):\s*(.+)'
        city_pattern = r'(?i)(city):\s*(.+)'
        isp_pattern = r'(?i)(isp|netname):\s*(.+)'
        asn_pattern = r'(?i)(asn|origin):\s*(.+)'
        
        organization = "Unknown"
        country = "Unknown"
        city = "Unknown"
        isp = "Unknown"
        asn = "Unknown"
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('%'):
                continue
                
            org_match = re.search(org_pattern, line)
            if org_match:
                organization = org_match.group(2).strip()
                
            country_match = re.search(country_pattern, line)
            if country_match:
                country = country_match.group(2).strip()
                
            city_match = re.search(city_pattern, line)
            if city_match:
                city = city_match.group(2).strip()
                
            isp_match = re.search(isp_pattern, line)
            if isp_match:
                isp = isp_match.group(2).strip()
                
            asn_match = re.search(asn_pattern, line)
            if asn_match:
                asn = asn_match.group(2).strip()
        
        # Get hostname
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            hostname = "Unknown"
        
        # IP address properties
        ip_obj = ipaddress.ip_address(ip_address)
        
        return {
            'ip': ip_address,
            'hostname': hostname,
            'organization': organization,
            'country': country,
            'city': city,
            'isp': isp,
            'asn': asn,
            'is_private': ip_obj.is_private,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
            'is_loopback': ip_obj.is_loopback,
            'version': ip_obj.version,
            'whois_data': whois_text,
            'status': 'success'
        }
        
    except Exception as e:
        return {
            'ip': ip_address,
            'error': f'Failed to parse whois data: {str(e)}',
            'whois_data': whois_text,
            'status': 'parse_error'
        }

@bp.route('/whois')
@login_required
@block_scanners
def whois_lookup():
    """Whois IP lookup page."""
    return render_template('whois.html')

@bp.route('/api/whois/<ip_address>')
@login_required
def api_whois_lookup(ip_address):
    """API endpoint for whois lookup."""
    try:
        current_app.logger.info(f"Whois lookup requested for IP: {ip_address}")
        
        # Check cache first
        cache_key = f'whois_{ip_address}'
        cached_result = cache.get(cache_key)
        if cached_result:
            return jsonify({'status': 'success', 'data': cached_result, 'cached': True})
        
        # Perform lookup
        result = perform_whois_lookup(ip_address)
        
        if 'error' not in result:
            # Cache successful results for 1 hour
            cache.set(cache_key, result, timeout=3600)
            
            # Log the lookup
            log_entry = Log(
                level='INFO',
                message=f'Whois lookup performed for IP: {ip_address}',
                user_id=current_user.id,
                ip_address=request.remote_addr,
                event_type='whois_lookup'
            )
            db.session.add(log_entry)
            db.session.commit()
        
        return jsonify({'status': 'success', 'data': result, 'cached': False})
        
    except Exception as e:
        current_app.logger.error(f"Error in whois lookup for {ip_address}: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/whois', methods=['POST'])
@login_required
def api_whois_lookup_post():
    """API endpoint for whois lookup via POST."""
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'status': 'error', 'error': 'IP address required'}), 400
        
        ip_address = data['ip'].strip()
        if not ip_address:
            return jsonify({'status': 'error', 'error': 'IP address cannot be empty'}), 400
        
        return api_whois_lookup(ip_address)
        
    except Exception as e:
        current_app.logger.error(f"Error in POST whois lookup: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500
     
@bp.route('/favicon.ico')
def favicon():
    try:
        return current_app.send_static_file('favicon.ico')
    except:
        return '', 204

@bp.app_errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error={
        'code': 404,
        'name': 'Not Found',
        'description': 'The requested page was not found.'
    }), 404

@bp.app_errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error={
        'code': 500,
        'name': 'Internal Server Error',
        'description': 'An unexpected error has occurred.'
    }), 500

@socketio.on('connect')
def handle_connect():
    current_app.logger.debug("SocketIO client connected")
    emit('status_update', {'message': 'Connected'})



@bp.route('/api/performance/metric', methods=['POST'])
@login_required
def api_performance_metric():
    """Endpoint to receive performance metrics from client."""
    try:
        data = request.get_json()
        if data:
            current_app.logger.info(f"Performance Metric: {data.get('milestone')} - {data.get('time')}ms - {data.get('url')}")
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@bp.route('/api/performance/stats')
@login_required
@require_admin
def api_performance_stats():
    """Get performance statistics (admin only)."""
    try:
        stats = performance_monitor.get_performance_stats()
        slow_requests = performance_monitor.slow_requests[-20:]  # Last 20 slow requests
        
        return jsonify({
            'status': 'success',
            'data': {
                'endpoint_stats': stats,
                'slow_requests': slow_requests,
                'total_slow_requests': len(performance_monitor.slow_requests)
            }
        })
    except Exception as e:
        current_app.logger.error(f"Error getting performance stats: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500



