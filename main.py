# Add this to the beginning of main.py after imports

import os
import sys
import logging
import threading
from logging.handlers import RotatingFileHandler
from sqlalchemy import text
from flask import Flask
from logging.handlers import RotatingFileHandler
from web_interface.app import app, db, socketio, migrate
from models import User
from werkzeug.security import generate_password_hash

# Enhanced startup configuration
def configure_application():
    """Configure the application with proper context and error handling."""
    
    # Set environment variables for better context handling
    os.environ['FLASK_SKIP_DOTENV'] = '1'  # Skip .env loading issues
    
    # Configure logging before anything else
    setup_enhanced_logging()
    
    # Import app components after logging is configured
    try:
        from web_interface.app import app, db, socketio, migrate
        from models import User
        
        logging.info("Successfully imported Flask application components")
        return app, db, socketio, migrate
        
    except ImportError as e:
        logging.error(f"Failed to import application components: {e}")
        sys.exit(1)

def setup_enhanced_logging():
    """Set up comprehensive logging with error handling."""
    try:
        # Create logs directory
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        # Configure root logger first
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Clear any existing handlers to prevent duplicates
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create detailed formatter
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)8s] %(name)s:%(lineno)d %(funcName)s() - %(message)s'
        )
        
        # File handler with rotation
        try:
            file_handler = RotatingFileHandler(
                'logs/esl.log',
                maxBytes=10485760,  # 10MB
                backupCount=10
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)
            root_logger.addHandler(file_handler)
        except Exception as file_error:
            print(f"Warning: Could not set up file logging: {file_error}")
        
        # Console handler for development
        if os.getenv('FLASK_ENV') != 'production':
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            console_handler.setLevel(logging.INFO)
            root_logger.addHandler(console_handler)
        
        # Reduce noise from third-party libraries
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
        logging.getLogger('socketio').setLevel(logging.WARNING)
        logging.getLogger('engineio').setLevel(logging.WARNING)
        
        logging.info("Enhanced logging system initialized successfully")
        
    except Exception as e:
        print(f"Critical error setting up logging: {e}")
        sys.exit(1)

def init_database_with_context(app, db):
    """Initialize database with proper context handling."""
    try:
        # Ensure database directory exists
        os.makedirs('db', exist_ok=True)
        
        with app.app_context():
            try:
                # Create all tables
                db.create_all()
                logging.info("Database tables created/verified successfully")
                
                # Test database connection
                # The fix is on the line below
                db.session.execute(text('SELECT 1'))
                db.session.commit()
                logging.info("Database connection test successful")
                
                # Create admin user if needed
                create_admin_user_if_needed(db)
                
            except Exception as db_error:
                logging.error(f"Database operation failed: {db_error}")
                db.session.rollback()
                raise
                
    except Exception as e:
        logging.error(f'Database initialization error: {e}')
        sys.exit(1)

def create_admin_user_if_needed(db):
    """Create admin user with proper error handling."""
    try:
        from models import User
        
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_password = os.getenv('ADMIN_PASSWORD', 'AdminPassword123!')
            
            admin = User(
                username='admin',
                email='admin@example.com',
                role='admin',
                is_active=True,
                password_change_required=True
            )
            admin.set_password(admin_password)
            
            db.session.add(admin)
            db.session.commit()
            
            logging.info('Admin user created successfully')
            logging.warning('Admin password set from environment or default')
        else:
            logging.info('Admin user already exists')
            
    except Exception as e:
        logging.error(f"Error creating admin user: {e}")
        db.session.rollback()
        raise

def setup_application_context_handlers(app):
    """Set up application context handlers to prevent context errors."""
    
    @app.before_first_request
    def before_first_request():
        """Initialize application state before first request."""
        try:
            logging.info("Processing first request - initializing application state")
            
            # Initialize performance monitoring
            from web_interface.performance_optimizer import performance_monitor
            app.extensions['performance_monitor'] = performance_monitor
            
            # Warm up cache
            from cache import cache
            cache.set('app_initialized', True, timeout=3600)
            logging.info("Application state initialized successfully")
            
        except Exception as e:
            logging.error(f"Error in before_first_request: {e}")
    
    @app.before_request
    def before_request():
        """Enhanced before request handler with error protection."""
        try:
            from flask import g
            from web_interface.performance_optimizer import performance_monitor
            
            # Start performance monitoring
            performance_monitor.start_request_timer()
            
            # Initialize script tracking
            g.loaded_scripts = getattr(g, 'loaded_scripts', [])
            
        except Exception as e:
            logging.error(f"Error in before_request: {e}")
    
    @app.after_request
    def after_request(response):
        """Enhanced after request handler with comprehensive error handling."""
        try:
            from web_interface.performance_optimizer import performance_monitor
            
            # End performance monitoring
            performance_monitor.end_request_timer(response)
            
            # Set security headers
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
            
        except Exception as e:
            logging.error(f"Error in after_request: {e}")
            
        return response
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        """Global exception handler with context error handling."""
        import traceback
        
        error_msg = str(e)
        
        # Log the full exception
        logging.error(f"Unhandled exception: {error_msg}")
        logging.error(f"Exception type: {type(e).__name__}")
        logging.error(f"Traceback:\n{traceback.format_exc()}")
        
        # Handle specific context errors
        if "outside of application context" in error_msg or "outside of request context" in error_msg:
            logging.error("Context error detected - attempting recovery")
            try:
                return render_template('error.html', error={
                    'code': 500,
                    'name': 'Application Context Error',
                    'description': 'A context error occurred. Please refresh the page and try again.'
                }), 500
            except:
                return "Application context error. Please refresh the page.", 500
        
        # Rollback any pending database transactions
        try:
            from models import db
            db.session.rollback()
        except Exception:
            pass
        
        # Return appropriate error response
        try:
            if hasattr(e, 'code'):
                return render_template('error.html', error={
                    'code': e.code,
                    'name': getattr(e, 'name', 'Error'),
                    'description': getattr(e, 'description', str(e))
                }), e.code
            else:
                return render_template('error.html', error={
                    'code': 500,
                    'name': 'Internal Server Error',
                    'description': 'An unexpected error occurred.'
                }), 500
        except Exception as render_error:
            logging.error(f"Error rendering error page: {render_error}")
            return f"Internal server error: {error_msg}", 500

def start_background_services(app):
    """Start background services with proper context handling."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        
        scheduler = BackgroundScheduler()
        
        # Add jobs with app context
        def run_with_context(func):
            with app.app_context():
                try:
                    func()
                except Exception as e:
                    logging.error(f"Background job error: {e}")
        
        # Schedule tasks
        scheduler.add_job(
            func=lambda: run_with_context(lambda: None),  # Placeholder for antivirus
            trigger="interval", 
            seconds=3600,
            id='antivirus_check'
        )
        
        def check_password_expiration():
            try:
                from models import User, AuditLog, db
                from datetime import datetime
                
                expired_users = User.query.filter(
                    User.password_expires <= datetime.utcnow()
                ).all()
                
                for user in expired_users:
                    user.password_change_required = True
                    logging.warning(f'Password expired for user: {user.username}')
                    
                    audit = AuditLog(
                        user_id=user.id,
                        action='password_expired',
                        details='Password expired and change required'
                    )
                    db.session.add(audit)
                
                db.session.commit()
                
            except Exception as e:
                logging.error(f"Error in check_password_expiration: {e}")
                try:
                    db.session.rollback()
                except:
                    pass
        
        scheduler.add_job(
            func=lambda: run_with_context(check_password_expiration),
            trigger="interval", 
            hours=24,
            id='password_expiration_check'
        )
        
        scheduler.start()
        logging.info("Background services started successfully")
        
        return scheduler
        
    except Exception as e:
        logging.error(f"Error starting background services: {e}")
        return None

def run_application():
    """Main application runner with comprehensive error handling."""
    try:
        # Configure application
        app, db, socketio, migrate = configure_application()
        
        # Initialize database with context
        init_database_with_context(app, db)
        
        # Setup context handlers
        setup_application_context_handlers(app)
        
        # Start background services
        scheduler = start_background_services(app)
        
        # Validate configuration
        required_config = ['SECRET_KEY', 'SQLALCHEMY_DATABASE_URI']
        missing_config = [key for key in required_config if not app.config.get(key)]
        
        if missing_config:
            logging.error(f"Missing required configuration: {missing_config}")
            sys.exit(1)
        
        # Log startup information
        logging.info(f"Environment: {os.getenv('FLASK_ENV', 'development')}")
        logging.info(f"Debug mode: {app.debug}")
        logging.info(f"Database: {app.config.get('SQLALCHEMY_DATABASE_URI', 'Not configured')}")
        
        # Check for required files
        osv_scanner_path = os.path.join(os.getcwd(), "osv-scanner_windows_amd64.exe")
        if os.path.exists(osv_scanner_path):
            logging.info(f"OSV Scanner found: {osv_scanner_path}")
        else:
            logging.warning(f"OSV Scanner not found: {osv_scanner_path}")
        
        # Start the application
        if os.getenv('FLASK_ENV') == 'production':
            logging.info("Starting production server")
            try:
                socketio.run(
                    app,
                    host='0.0.0.0',
                    port=443,
                    ssl_context=('cert.pem', 'key.pem'),
                    debug=False
                )
            except Exception as prod_error:
                logging.error(f"Production server failed: {prod_error}")
                logging.info("Falling back to HTTP")
                socketio.run(app, host='0.0.0.0', port=5000, debug=False)
        else:
            logging.info("Starting development server")
            try:
                if os.getenv('USE_SOCKETIO', 'true').lower() == 'true':
                    socketio.run(
                        app, 
                        debug=True, 
                        host='0.0.0.0', 
                        port=5000,
                        use_reloader=False  # Prevent context issues
                    )
                else:
                    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
            except Exception as dev_error:
                logging.error(f"Development server error: {dev_error}")
                logging.info("Falling back to basic Flask server")
                app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
        
    except KeyboardInterrupt:
        logging.info("Application stopped by user")
    except Exception as e:
        logging.error(f"Critical application error: {e}")
        sys.exit(1)
    finally:
        # Cleanup
        try:
            if 'scheduler' in locals() and scheduler:
                scheduler.shutdown(wait=True)
                logging.info("Background services stopped")
        except:
            pass

if __name__ == '__main__':
    
    # Run application
    if os.getenv('FLASK_ENV') == 'production':
        socketio.run(
            app,
            host='0.0.0.0',
            port=443,
            ssl_context=('cert.pem', 'key.pem'),
            debug=False
        )
    else:
        try:
            # For development, use the Flask development server without SocketIO's run method
            # to avoid the cors_allowed_origins parameter issue
            if os.getenv('USE_SOCKETIO') == 'true':
                socketio.run(app, debug=True, host='0.0.0.0', port=5000)
            else:
                app.run(debug=True, host='0.0.0.0', port=5000)
        except Exception as e:
            app.logger.error(f"Error starting server: {e}")
            # Fallback to regular Flask development server
            app.run(debug=True, host='0.0.0.0', port=5000)

    run_application()        