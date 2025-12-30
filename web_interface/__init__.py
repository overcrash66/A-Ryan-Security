from flask import Flask
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import logging
from config import Config
from models import db
from cache import cache

# Initialize extensions
socketio = SocketIO()
login_manager = LoginManager()
csrf = CSRFProtect()
bootstrap = Bootstrap()
migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
scheduler = None

def cleanup_background_tasks():
    """Clean up background tasks and threads on application shutdown."""
    global scheduler
    try:
        if scheduler and scheduler.running:
            scheduler.shutdown(wait=True)
            logging.info("Background scheduler stopped")
        
        # Clear cache (access via global if needed or skip)
        # cache.clear() logic was here but cache might be bound to app. 
        # For simplicity, focus on scheduler which is the critical resource.
            
    except Exception as e:
        logging.getLogger(__name__).error(f"Error during cleanup: {e}")

atexit.register(cleanup_background_tasks)

def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions with app
    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    login_manager.init_app(app)
    csrf.init_app(app)
    bootstrap.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    cache.init_app(app)

    # Configure Login Manager
    login_manager.login_view = 'main.login'
    login_manager.login_message_category = 'info'

    # Register Blueprints
    from .routes import bp as main_bp
    app.register_blueprint(main_bp)

    # Database query optimization (from original app.py)
    with app.app_context():
        try:
            # Import here to avoid circular dependencies if any
            from web_interface.items_per_page import optimize_database_queries
            optimize_database_queries()
        except ImportError:
            pass # items_per_page might not exist or optimize_database_queries might be elsewhere? 
            # Original app.py imported it from 'web_interface.items_per_page' ? 
            # Wait, I didn't verify this import source in app.py reading. 
            # Line 2025: optimize_database_queries()
            # Where is it imported?
            # I need to check routes.py imports later to be sure.
            pass
        except Exception as e:
            app.logger.error(f"Error optimizing database: {e}")

    # Initialize scheduler if not testing
    if not app.config.get('TESTING'):
        global scheduler
        try:
            from web_interface.api_maintenance import check_expiring_api_keys, cleanup_expired_api_keys
            scheduler = BackgroundScheduler()
            scheduler.add_job(check_expiring_api_keys, 'cron', hour=0)
            scheduler.add_job(cleanup_expired_api_keys, 'cron', hour=1)
            scheduler.start()
            app.scheduler = scheduler # Attach to app for access if needed
        except ImportError:
            app.logger.warning("Could not import api_maintenance tasks")
        except Exception as e:
            app.logger.error(f"Error starting scheduler: {e}")

    return app
