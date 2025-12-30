import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Security settings - NO HARDCODED SECRETS
    SECRET_KEY = os.getenv('SECRET_KEY')
    if not SECRET_KEY:
        if os.getenv('FLASK_ENV') == 'production':
            raise ValueError("SECRET_KEY environment variable must be set")
        SECRET_KEY = 'dev-default-key-for-local-testing'
    
    if len(SECRET_KEY) < 32 and os.getenv('FLASK_ENV') == 'production':
        raise ValueError("SECRET_KEY must be at least 32 characters long")

    # Database settings
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL') or 'sqlite:///app.db'
    
    # Validation/Conversion for SQLite paths (Fix for Windows relative path issues)
    if SQLALCHEMY_DATABASE_URI.startswith('sqlite:///'):
        db_path = SQLALCHEMY_DATABASE_URI.replace('sqlite:///', '')
        # Check if it's a relative path (not starting with / or drive letter)
        if not os.path.isabs(db_path):
             # Convert to absolute path
             abs_path = os.path.abspath(db_path)
             # SQLAlchemy requires forward slashes even on Windows for URIs
             # but on Windows os.path.abspath uses backslashes
             abs_path = abs_path.replace('\\', '/')
             SQLALCHEMY_DATABASE_URI = f'sqlite:///{abs_path}'
             
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.getenv('DB_POOL_SIZE', '10')),
        'max_overflow': int(os.getenv('DB_MAX_OVERFLOW', '20')),
        'pool_timeout': int(os.getenv('DB_POOL_TIMEOUT', '30')),
        'pool_recycle': int(os.getenv('DB_POOL_RECYCLE', '1800')),
    }

    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = os.getenv('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = os.getenv('FLASK_ENV') == 'production'
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # Rate limiting - use memory storage instead of Redis
    RATELIMIT_DEFAULT = "100 per day"
    RATELIMIT_STORAGE_URL = "memory://"

    # Cache settings - use SimpleCache instead of Redis
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 300

    # CSRF protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Flask-Login settings
    LOGIN_DISABLED = False

    # Flask environment
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = FLASK_ENV == 'development'