from flask_caching import Cache
from flask import Flask

# Create a SimpleCache instance
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})

# Create a minimal Flask app for cache initialization
_cache_app = Flask(__name__)
_cache_app.config['CACHE_TYPE'] = 'SimpleCache'

def init_cache(app):
    """Initialize cache with proper configuration."""
    try:
        cache.init_app(app, config={'CACHE_TYPE': 'SimpleCache'})
        app.logger.info("Cache initialized successfully")
    except Exception as e:
        app.logger.error(f"Error initializing cache: {e}")
        # Fallback to null cache
        cache.init_app(app, config={'CACHE_TYPE': 'null'})

# Initialize cache with the minimal app for testing
try:
    cache.init_app(_cache_app)
except Exception:
    # If that fails, try with null cache
    cache.init_app(_cache_app, config={'CACHE_TYPE': 'null'})