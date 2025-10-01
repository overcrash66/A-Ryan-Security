import pytest
from models import User, db
from flask_jwt_extended import create_access_token
import json

def test_api_key_generation(client, app_ctx, test_user):
    """Test API key generation."""
    with app_ctx:
        # Generate API key
        test_user.generate_api_key()
        db.session.commit()
        
        assert test_user.api_key is not None
        assert len(test_user.api_key) > 32  # Should be sufficiently long

def test_protected_endpoint_with_api_key(client, app_ctx, test_user):
    """Test accessing protected endpoint with API key."""
    with app_ctx:
        # Generate API key
        api_key = test_user.generate_api_key()
        db.session.commit()
        
        # Try accessing a protected endpoint
        headers = {'X-API-Key': api_key}
        response = client.get('/api/status/av', headers=headers)
        assert response.status_code == 200

def test_protected_endpoint_with_invalid_api_key(client):
    """Test accessing protected endpoint with invalid API key."""
    headers = {'X-API-Key': 'invalid_key'}
    response = client.get('/api/status/av', headers=headers)
    assert response.status_code == 401

def test_protected_endpoint_with_jwt(client, app_ctx, test_user):
    """Test accessing protected endpoint with JWT."""
    with app_ctx:
        # First login to get a token
        response = client.post('/api/auth/login', json={
            'username': 'testuser',
            'password': 'testpass'
        })
        assert response.status_code == 200
        token_data = response.get_json()
        assert 'access_token' in token_data
        
        # Try accessing a protected endpoint
        headers = {'Authorization': f'Bearer {token_data["access_token"]}'}
        response = client.get('/api/status/av', headers=headers)
        assert response.status_code == 200

def test_admin_endpoint_with_non_admin_api_key(client, app_ctx, test_user):
    """Test accessing admin endpoint with non-admin API key."""
    with app_ctx:
        # Generate API key for non-admin user
        api_key = test_user.generate_api_key()
        db.session.commit()
        
        # Try accessing an admin endpoint
        headers = {'X-API-Key': api_key}
        response = client.get('/api/admin/users', headers=headers)
        assert response.status_code == 403  # Should be forbidden for non-admin users

def test_admin_endpoint_with_admin_api_key(client, app_ctx):
    """Test accessing admin endpoint with admin API key."""
    with app_ctx:
        # Create and get admin user
        admin = User.query.filter_by(username='admin').first()
        api_key = admin.generate_api_key()
        db.session.commit()
        
        # Try accessing an admin endpoint
        headers = {'X-API-Key': api_key}
        response = client.get('/api/admin/users', headers=headers)
        assert response.status_code == 200
        
        # Verify response data
        data = response.get_json()
        assert data['status'] == 'success'
        assert isinstance(data['data'], list)  # Should return list of users

def test_api_auth_endpoints(client, app_ctx, test_user):
    """Test the API authentication endpoints."""
    with app_ctx:
        # Test login with valid credentials
        response = client.post('/api/auth/login', json={
            'username': 'testuser',
            'password': 'testpass'
        })
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert data['expires_in'] == 3600
        assert data['token_type'] == 'Bearer'
        access_token = data['access_token']
        
        # Test API key generation using JWT
        headers = {'Authorization': f'Bearer {access_token}'}
        response = client.post('/api/auth/token', headers=headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'api_key' in data
        assert 'expires_at' in data
        
        # Test API key usage
        headers = {'X-API-Key': data['api_key']}
        response = client.get('/api/status/av', headers=headers)
        assert response.status_code == 200
        
        # Test login with invalid credentials
        response = client.post('/api/auth/login', json={
            'username': 'testuser',
            'password': 'wrongpass'
        })
        assert response.status_code == 401