"""
AI Configuration Service Module
Handles user-configurable AI settings including API URL, provider, API keys, and default models.
"""
import os
import logging
import requests
from cryptography.fernet import Fernet
import base64

from models import db, AIConfig

logger = logging.getLogger(__name__)

# Default configuration values
DEFAULT_CONFIG = {
    'provider': 'ollama',
    'api_url': 'http://127.0.0.1:11434',
    'default_model': 'qwen2.5-coder:3b',
    'is_enabled': True
}

# Fallback port for backward compatibility
FALLBACK_PORT = 11435


def _get_encryption_key(key_version=1):
    """
    Generate encryption key from Flask SECRET_KEY.
    Uses PBKDF2 with salt for proper key derivation.
    Supports key version for future rotation.
    
    Args:
        key_version: Version number for key rotation (default: 1)
    """
    from flask import current_app
    try:
        secret = current_app.config.get('SECRET_KEY')
    except RuntimeError:
        pass
    
    if not secret:
        raise ValueError("SECRET_KEY must be configured for API key encryption. Please set SECRET_KEY in your Flask config.")
    
    # Include key version in the secret to allow future rotation
    key_with_version = f"{secret}_v{key_version}"
    
    # Use PBKDF2 with a fixed salt for key derivation (better than simple SHA256)
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    
    # Use salt from environment variable (unique per deployment) with fallback to static constant
    salt = os.environ.get('ENCRYPTION_SALT')
    if not salt:
        # Static fallback salt for backward compatibility
        salt = 'ai_config_fallback_salt_2024'
        logger.warning("Using fallback encryption salt. For better security, set ENCRYPTION_SALT environment variable.")
    
    salt = salt.encode()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key_bytes = kdf.derive(key_with_version.encode())
    return base64.urlsafe_b64encode(key_bytes)


def encrypt_api_key(key, key_version=1):
    """
    Encrypt API key using Fernet encryption.
    
    Args:
        key: Plain text API key to encrypt
        key_version: Encryption key version for future rotation
        
    Returns:
        Encrypted key as string with key version prefix, or None if input is None/empty
    """
    if not key:
        return None
    
    try:
        fernet = Fernet(_get_encryption_key(key_version))
        encrypted = fernet.encrypt(key.encode())
        # Prefix with version for future key rotation support
        return f"v{key_version}:{encrypted.decode()}"
    except Exception as e:
        logger.error(f"Failed to encrypt API key: {e}")
        return None


def decrypt_api_key(encrypted_key):
    """
    Decrypt API key for use in API calls.
    Supports key version prefix for future key rotation.
    
    Args:
        encrypted_key: Encrypted API key string (optionally prefixed with version like "v1:...")
        
    Returns:
        Decrypted plain text API key, or None if input is None/empty or decryption fails
    """
    if not encrypted_key:
        return None
    
    try:
        # Check for version prefix
        if encrypted_key.startswith('v') and ':' in encrypted_key:
            version_part, key_part = encrypted_key.split(':', 1)
            key_version = int(version_part[1:])  # Extract version number
        else:
            key_version = 1  # Default version for old keys
            key_part = encrypted_key
        
        fernet = Fernet(_get_encryption_key(key_version))
        decrypted = fernet.decrypt(key_part.encode())
        return decrypted.decode()
    except Exception as e:
        logger.error(f"Failed to decrypt API key: {e}")
        return None


def get_default_config():
    """
    Get system default AI configuration.
    
    Returns:
        Dictionary with default configuration values
    """
    return DEFAULT_CONFIG.copy()


def get_ai_config(user_id):
    """
    Get user's AI configuration or system default if not configured.
    
    Args:
        user_id: ID of the user to get config for
        
    Returns:
        Dictionary with configuration (api_url, provider, default_model, is_enabled, api_key)
    """
    if user_id is None:
        return get_default_config()
    
    try:
        config = AIConfig.query.filter_by(user_id=user_id).first()
        
        if config:
            return {
                'provider': config.provider,
                'api_url': config.api_url,
                'api_key': config.api_key,  # Returns encrypted key
                'default_model': config.default_model,
                'is_enabled': config.is_enabled,
                'created_at': config.created_at,
                'updated_at': config.updated_at
            }
        else:
            # Return default config if user hasn't configured anything
            return get_default_config()
    except Exception as e:
        logger.error(f"Error fetching AI config for user {user_id}: {e}")
        return get_default_config()


def validate_ai_config(config_data):
    """
    Validate AI configuration data before saving.
    
    Args:
        config_data: Dictionary with configuration to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    from schemas import AIConfigSchema
    
    schema = AIConfigSchema()
    errors = schema.validate(config_data)
    
    if errors:
        return False, errors
    
    return True, None


def update_ai_config(user_id, config_data):
    """
    Save or update user's AI configuration.
    
    Args:
        user_id: ID of the user
        config_data: Dictionary with configuration data
        
    Returns:
        Tuple of (success, message)
    """
    # Validate configuration
    is_valid, errors = validate_ai_config(config_data)
    if not is_valid:
        return False, f"Validation errors: {errors}"
    
    try:
        # Check if config already exists
        config = AIConfig.query.filter_by(user_id=user_id).first()
        
        if config:
            # Update existing config
            config.provider = config_data.get('provider', 'ollama')
            config.api_url = config_data.get('api_url', 'http://127.0.0.1:11434')
            config.default_model = config_data.get('default_model', 'qwen2.5-coder:3b')
            config.is_enabled = config_data.get('is_enabled', True)
            
            # Encrypt and save API key if provided, or clear if explicitly set to empty
            if 'api_key' in config_data:
                if config_data['api_key'] == '':
                    # Explicit clear request
                    config.api_key = None
                elif config_data['api_key']:
                    encrypted = encrypt_api_key(config_data['api_key'])
                    if encrypted is None:
                        return False, "Failed to encrypt API key. Please try again."
                    config.api_key = encrypted
        else:
            # Create new config
            config = AIConfig(
                user_id=user_id,
                provider=config_data.get('provider', 'ollama'),
                api_url=config_data.get('api_url', 'http://127.0.0.1:11434'),
                default_model=config_data.get('default_model', 'qwen2.5-coder:3b'),
                is_enabled=config_data.get('is_enabled', True),
                api_key=encrypt_api_key(config_data['api_key']) if config_data.get('api_key') and config_data['api_key'] != '' else None
            )
            db.session.add(config)
        
        db.session.commit()
        logger.info(f"AI configuration updated for user {user_id}")
        return True, "Configuration saved successfully"
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating AI config for user {user_id}: {e}")
        return False, "Failed to save configuration. Please try again."


def _is_safe_url(url):
    """
    Validate URL to prevent SSRF attacks.
    Allows http/https to public IPs/hostnames and loopback addresses (127.0.0.0/8, ::1).
    Blocks private IP ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x) to prevent SSRF to internal networks.
    
    Args:
        url: URL string to validate
        
    Returns:
        True if URL is safe, False otherwise
    """
    from urllib.parse import urlparse
    import ipaddress
    
    # Block common localhost names that shouldn't be used
    localhost_blocklist = ('localhost.localdomain',)
    
    try:
        parsed = urlparse(url)
        
        # Only allow http and https
        if parsed.scheme not in ('http', 'https'):
            return False
        
        # Must have a valid network location
        if not parsed.netloc:
            return False
        
        # Check if the host is a private IP or localhost
        hostname = parsed.hostname
        if not hostname:
            return False
        
        # Block specific localhost names (but not IP-based loopback)
        if hostname.lower() in localhost_blocklist:
            return False
        
        # Try to resolve and check IP
        try:
            # Get IP from hostname
            import socket
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
            
            # Block private IP ranges (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
            # but allow loopback (127.0.0.0/8 and ::1)
            if ip.is_private and not ip.is_loopback:
                return False
            
            # Block reserved IPs but allow loopback
            if ip.is_reserved and not ip.is_loopback:
                return False
            
            # Block IPv6 link-local addresses (fe80::/10)
            if ip.version == 6 and ip.is_link_local:
                return False
            
        except socket.gaierror:
            # If we can't resolve, deny the URL to prevent SSRF via DNS rebinding
            logger.warning(f"DNS resolution failed for {hostname} - denying to prevent SSRF")
            return False
        except ValueError:
            # Not a valid IP, check hostname-based restrictions below
            pass
        
        return True
        
    except Exception:
        return False


def get_available_models(api_url):
    """
    Fetch available models from Ollama API.
    
    Args:
        api_url: Base URL of the Ollama API
        
    Returns:
        List of model names, or empty list on error
    """
    # Validate URL to prevent SSRF
    if not _is_safe_url(api_url):
        logger.warning(f"Blocked SSRF attempt: {api_url}")
        return []
    
    try:
        # Try to get models from Ollama
        response = requests.get(f"{api_url}/api/tags", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            models = [model['name'] for model in data.get('models', [])]
            logger.info(f"Retrieved {len(models)} models from {api_url}")
            return models
        else:
            logger.warning(f"Failed to get models from {api_url}: HTTP {response.status_code}")
            return []
            
    except requests.exceptions.ConnectionError:
        logger.warning(f"Could not connect to {api_url}")
        return []
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout connecting to {api_url}")
        return []
    except Exception as e:
        logger.error(f"Error fetching models from {api_url}: {e}")
        return []


def test_connection(api_url, provider='ollama'):
    """
    Test connection to AI provider.
    
    Args:
        api_url: Base URL of the API
        provider: Provider type (ollama, openai, azure)
        
    Returns:
        Tuple of (success, message)
    """
    if provider == 'ollama':
        try:
            # Try to get models as a connection test
            models = get_available_models(api_url)
            
            if models:
                return True, f"Connected successfully. Found {len(models)} models."
            else:
                return False, "Connected but no models found. Make sure Ollama is running and has models downloaded."
                
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False, f"Connection failed: {str(e)}"
    
    # Add other providers as needed
    return False, f"Provider '{provider}' not yet supported"


def get_decrypted_api_key(user_id):
    """
    Get decrypted API key for a user.
    
    Args:
        user_id: ID of the user
        
    Returns:
        Decrypted API key or None
    """
    if user_id is None:
        return None
    
    config = get_ai_config(user_id)
    
    if config is None:
        return None
    
    encrypted_key = config.get('api_key')
    
    if encrypted_key is None:
        logger.warning(f"No encrypted API key found for user lookup")
        return None
    
    return decrypt_api_key(encrypted_key)