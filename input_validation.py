import os
import re
import logging
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class InputValidator:
    """Comprehensive input validation for security scanning application."""

    # Dangerous path patterns
    DANGEROUS_PATHS = [
        'C:\\Windows\\System32',
        'C:\\Windows\\SysWOW64',
        'C:\\Program Files\\WindowsApps',
        '/etc',
        '/usr/bin',
        '/bin',
        '/sys',
        '/proc'
    ]

    # Allowed file extensions for scanning
    ALLOWED_EXTENSIONS = {
        '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.hpp',
        '.go', '.rs', '.php', '.rb', '.pl', '.sh', '.bat', '.cmd',
        '.json', '.xml', '.yaml', '.yml', '.toml', '.ini', '.cfg',
        '.txt', '.md', '.html', '.css', '.scss', '.sass', '.less',
        '.sql', '.db', '.sqlite', '.lock', '.requirements', '.package'
    }

    @classmethod
    def validate_scan_path(cls, path):
        """Validate scan path for security and accessibility."""
        if not path:
            raise ValueError("Scan path cannot be empty")

        # Normalize and validate path
        try:
            normalized_path = os.path.normpath(path)
            if not normalized_path:
                raise ValueError("Invalid path format")
        except Exception as e:
            raise ValueError(f"Path normalization failed: {str(e)}")

        # Check for path traversal attempts
        if '..' in normalized_path or normalized_path.startswith('\\\\'):
            raise ValueError("Path traversal attempts detected")

        # Check for dangerous system paths
        path_lower = normalized_path.lower()
        for dangerous_path in cls.DANGEROUS_PATHS:
            if path_lower.startswith(dangerous_path.lower()):
                raise ValueError(f"Cannot scan sensitive system directory: {normalized_path}")

        # Check if path exists
        if not os.path.exists(normalized_path):
            raise ValueError(f"Path does not exist: {normalized_path}")

        # Check if path is accessible
        if not os.access(normalized_path, os.R_OK):
            raise ValueError(f"Cannot access path (permission denied): {normalized_path}")

        # Check if it's a directory or valid file
        if not (os.path.isdir(normalized_path) or os.path.isfile(normalized_path)):
            raise ValueError(f"Path must be a directory or file: {normalized_path}")

        # Additional validation for files
        if os.path.isfile(normalized_path):
            cls._validate_scan_file(normalized_path)

        return normalized_path

    @classmethod
    def _validate_scan_file(cls, file_path):
        """Validate individual file for scanning."""
        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() not in cls.ALLOWED_EXTENSIONS:
            logger.warning(f"File extension {ext} not in allowed list for {file_path}")

        # Check file size (max 100MB)
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB
                raise ValueError(f"File too large for scanning: {file_size} bytes")
        except OSError as e:
            raise ValueError(f"Cannot determine file size: {str(e)}")

    @classmethod
    def validate_ip_address(cls, ip_address):
        """Validate IP address format."""
        if not ip_address:
            raise ValueError("IP address cannot be empty")

        # Remove whitespace
        ip_address = ip_address.strip()

        # Basic IP validation
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip_address):
            raise ValueError(f"Invalid IP address format: {ip_address}")

        # Validate each octet
        octets = ip_address.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                raise ValueError(f"Invalid IP address octet: {octet}")

        return ip_address

    @classmethod
    def validate_port(cls, port):
        """Validate port number."""
        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValueError(f"Port must be between 1 and 65535: {port}")
            return port_num
        except (ValueError, TypeError):
            raise ValueError(f"Invalid port number: {port}")

    @classmethod
    def validate_url(cls, url):
        """Validate URL format."""
        if not url:
            raise ValueError("URL cannot be empty")

        url = url.strip()

        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid URL format: {url}")

            if parsed.scheme not in ['http', 'https']:
                raise ValueError(f"URL must use HTTP or HTTPS: {url}")

            return url
        except Exception as e:
            raise ValueError(f"URL validation failed: {str(e)}")

    @classmethod
    def sanitize_filename(cls, filename):
        """Sanitize filename to prevent path traversal."""
        if not filename:
            raise ValueError("Filename cannot be empty")

        # Remove path separators and dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '', filename)

        # Remove control characters
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)

        # Limit length
        if len(sanitized) > 255:
            raise ValueError("Filename too long")

        if not sanitized:
            raise ValueError("Invalid filename after sanitization")

        return sanitized

    @classmethod
    def validate_username(cls, username):
        """Validate username format."""
        if not username:
            raise ValueError("Username cannot be empty")

        username = username.strip()

        # Length check
        if len(username) < 3 or len(username) > 64:
            raise ValueError("Username must be between 3 and 64 characters")

        # Character validation
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            raise ValueError("Username can only contain letters, numbers, hyphens, and underscores")

        return username

    @classmethod
    def validate_email(cls, email):
        """Validate email format."""
        if not email:
            raise ValueError("Email cannot be empty")

        email = email.strip()

        # Basic email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError(f"Invalid email format: {email}")

        # Length check
        if len(email) > 254:
            raise ValueError("Email too long")

        return email.lower()

    @classmethod
    def validate_password_strength(cls, password):
        """Validate password strength requirements."""
        if not password:
            raise ValueError("Password cannot be empty")

        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters long")

        # Check for required character types
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*" for c in password)

        if not (has_upper and has_lower and has_digit and has_special):
            raise ValueError("Password must contain uppercase, lowercase, digit, and special character (!@#$%^&*)")

        # Check for common weak patterns
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            raise ValueError("Password cannot contain repeated characters")

        return True

def validate_and_sanitize_scan_request(scan_path, ip_address=None, port=None):
    """Validate and sanitize a complete scan request."""
    try:
        # Validate scan path
        validated_path = InputValidator.validate_scan_path(scan_path)

        # Validate optional IP address
        validated_ip = None
        if ip_address:
            validated_ip = InputValidator.validate_ip_address(ip_address)

        # Validate optional port
        validated_port = None
        if port:
            validated_port = InputValidator.validate_port(port)

        return {
            'scan_path': validated_path,
            'ip_address': validated_ip,
            'port': validated_port,
            'is_valid': True
        }

    except ValueError as e:
        logger.warning(f"Scan request validation failed: {str(e)}")
        return {
            'scan_path': scan_path,
            'ip_address': ip_address,
            'port': port,
            'is_valid': False,
            'error': str(e)
        }