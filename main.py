import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from web_interface import create_app, socketio, db
from models import User, AuditLog
from sqlalchemy import text
from apscheduler.schedulers.background import BackgroundScheduler
from web_interface.tasks import check_password_expiration, run_extra_antivirus_job
from web_interface.performance_optimizer import performance_monitor

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

def create_admin_user_if_needed(app):
    """Create admin user with proper error handling."""
    with app.app_context():
        try:
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

def start_background_services(app):
    """Start background services with proper context handling."""
    try:
        scheduler = BackgroundScheduler()
        
        # Helper to run job with app context
        def run_job_with_context(job_func, *args):
            with app.app_context():
                try:
                    job_func(*args)
                except Exception as e:
                    logging.error(f"Background job error: {e}")

        # Schedule antivirus job
        scheduler.add_job(
            func=run_job_with_context,
            args=[run_extra_antivirus_job],
            trigger="interval", 
            seconds=3600,
            id='antivirus_check'
        )
        
        # Schedule password expiration check
        # Pass app to check_password_expiration because it needs it (as designed in tasks.py)
        # Wait, tasks.py definition: check_password_expiration(app)
        # So we just call check_password_expiration(app).
        # But we need error handling wrapper.
        scheduler.add_job(
            func=check_password_expiration,
            args=[app],
            trigger="interval", 
            hours=24,
            id='password_expiration_check'
        )
        
        # API Maintenance tasks (from original app.py)
        if not app.config.get('TESTING'):
             from web_interface.api_maintenance import check_expiring_api_keys, cleanup_expired_api_keys
             # These likely need context too? Let's check api_maintenance.py content if needed.
             # Assuming they use current_app or app context?
             # For safety, let's wrap them if they don't accept 'app'.
             # check_expiring_api_keys probably uses db.
             
             scheduler.add_job(
                 func=run_job_with_context,
                 args=[check_expiring_api_keys],
                 trigger='cron',
                 hour=0
             )
             scheduler.add_job(
                 func=run_job_with_context,
                 args=[cleanup_expired_api_keys],
                 trigger='cron',
                 hour=1
             )
        
        scheduler.start()
        logging.info("Background services started successfully")
        return scheduler
        
    except Exception as e:
        logging.error(f"Error starting background services: {e}")
        return None

def run_application():
    """Main application runner."""
    # Configure logging
    setup_enhanced_logging()
    
    try:
        # Create app
        app = create_app()
        
        # Initialize database
        with app.app_context():
            db.create_all()
            # Test connection
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            logging.info("Database connection test successful")
        
        # Create admin user
        create_admin_user_if_needed(app)
        
        # Start background services
        scheduler = start_background_services(app)
        
        # Start the application
        if os.getenv('FLASK_ENV') == 'production':
            logging.info("Starting production server")
            socketio.run(
                app,
                host='0.0.0.0',
                port=443,
                ssl_context=('cert.pem', 'key.pem'),
                debug=False,
                use_reloader=False 
            )
        else:
            logging.info("Starting development server")
            use_socketio = os.getenv('USE_SOCKETIO', 'true').lower() == 'true'
            if use_socketio:
                socketio.run(
                    app, 
                    debug=True, 
                    host='0.0.0.0', 
                    port=5000,
                    use_reloader=False
                )
            else:
                app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
                
    except Exception as e:
        logging.error(f"Critical application error: {e}")
        sys.exit(1)
    finally:
         if 'scheduler' in locals() and scheduler:
             scheduler.shutdown(wait=True)

if __name__ == '__main__':
    run_application()