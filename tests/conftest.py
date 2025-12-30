import pytest
import sys
import os
from flask import Flask, g

# Add the parent directory to the Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User
from flask_login import LoginManager, current_user
from flask_bootstrap import Bootstrap
from cache import init_cache

def create_test_app():
    """Create a Flask application configured for testing."""
    # Use the app factory
    from web_interface import create_app
    app = create_app()
    
    # Override config for testing
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SECRET_KEY': 'test-key',
        'WTF_CSRF_ENABLED': False,
        'CACHE_TYPE': 'SimpleCache',
        'SQLALCHEMY_ENGINE_OPTIONS': {}  # Clear engine options for SQLite
    })
    
    # Reset app state to allow re-init
    app._got_first_request = False

    # Remove existing sqlalchemy extension to allow re-init
    if 'sqlalchemy' in app.extensions:
        del app.extensions['sqlalchemy']

    # Re-initialize DB with new URI
    db.init_app(app)

    # Use the existing login_manager from web_interface extension init
    from web_interface import login_manager

    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID."""
        try:
            return User.query.get(int(user_id))
        except (TypeError, ValueError):
            return None

    with app.app_context():
        db.create_all()

        # Create default test users
        if not User.query.filter_by(username='testuser').first():
            user = User(username='testuser', email='test@test.com', role='user')
            user.set_password('testpass')
            user.password_change_required = False
            db.session.add(user)
            db.session.commit()

        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@test.com', role='admin')
            admin.set_password('adminpass')
            admin.password_change_required = False
            db.session.add(admin)
            db.session.commit()

    return app
#--new--
# @pytest.fixture
# def client():
#     app.config['TESTING'] = True
#     app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'  # Use a separate test database
#     with app.test_client() as client:
#         yield client

@pytest.fixture
def logged_in_client(client, app):
    with app.app_context():
        # Ensure test user exists
        if not User.query.filter_by(username='testuser').first():
            test_user = User(username='testuser', email='test@example.com', role='user')
            test_user.set_password('testpass')
            test_user.password_change_required = False
            db.session.add(test_user)
            db.session.commit()

        # Login the user
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass'
        })
        
        yield client
#--End-new--

@pytest.fixture(scope='function')
def app():
    """Create application for the tests."""
    app = create_test_app()
    return app

@pytest.fixture(scope='function')
def client(app):
    """Create test client."""
    with app.app_context():
        db.create_all()
        # Clear any cached login attempts to prevent rate limiting
        from cache import cache
        cache.clear()
        
        # Create test client within the app context
        with app.test_client() as client:
            yield client
        
        # Clean teardown
        try:
            db.session.remove()
            db.drop_all()
        except Exception:
            pass  # Ignore teardown errors

@pytest.fixture(scope='function')
def app_ctx(app):
    """Create app context for tests."""
    with app.app_context() as ctx:
        db.create_all()
        
        # Create test user if it doesn't exist
        if not User.query.filter_by(username='testuser').first():
            test_user = User(username='testuser', email='test@example.com', role='user')
            test_user.set_password('testpass')
            test_user.password_change_required = False
            db.session.add(test_user)
            db.session.commit()
            
        yield ctx
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope='function')
def test_user(app_ctx):
    """Get test user from app."""
    return User.query.filter_by(username='testuser').first()

# @pytest.fixture(scope='function')
# def logged_in_client(app, client):
#     """Create test client that's logged in."""
#     with app.app_context():
#         # Simulate a successful login by posting to the login route
#         response = client.post('/login', data={
#             'username': 'testuser',
#             'password': 'testpass'
#         }, follow_redirects=False)
#         return client
