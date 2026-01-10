"""
JWT (JSON Web Token) utilities for RS256 signing.

This module provides JWT generation capabilities using RSA-SHA256 (RS256)
algorithm for secure authentication with the Owl Browser HTTP server.

Note: This module uses the cryptography library for RSA operations.
Install with: pip install cryptography
"""

import base64
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Try to import cryptography, provide helpful error if not installed
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


def _check_cryptography():
    """Check if cryptography library is available."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise ImportError(
            "The 'cryptography' package is required for JWT authentication. "
            "Install it with: pip install cryptography"
        )


def _base64url_encode(data: bytes) -> str:
    """Base64URL encode bytes to string (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def _base64url_decode(data: str) -> bytes:
    """Base64URL decode string to bytes (handles missing padding)."""
    # Add padding if needed
    padding_needed = 4 - (len(data) % 4)
    if padding_needed != 4:
        data += '=' * padding_needed
    return base64.urlsafe_b64decode(data)


def _load_private_key(key_or_path: str):
    """
    Load RSA private key from PEM string or file path.

    Args:
        key_or_path: PEM-encoded private key string or path to key file

    Returns:
        RSA private key object
    """
    _check_cryptography()

    # Check if it's a PEM string
    if '-----BEGIN' in key_or_path or 'PRIVATE KEY' in key_or_path:
        key_pem = key_or_path.encode('utf-8')
    else:
        # Treat as file path
        if not os.path.exists(key_or_path):
            raise FileNotFoundError(f"Private key file not found: {key_or_path}")
        with open(key_or_path, 'rb') as f:
            key_pem = f.read()

    return serialization.load_pem_private_key(
        key_pem,
        password=None,
        backend=default_backend()
    )


def _sign_rs256(data: str, private_key) -> bytes:
    """Sign data using RS256 (RSA-SHA256)."""
    return private_key.sign(
        data.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )


@dataclass
class JWTConfig:
    """
    Configuration for JWT generation.

    Attributes:
        private_key: Path to RSA private key file or PEM string
        expires_in: Token validity in seconds (default: 3600 = 1 hour)
        refresh_threshold: Seconds before expiry to refresh (default: 300 = 5 min)
        issuer: Issuer claim (iss)
        subject: Subject claim (sub)
        audience: Audience claim (aud)
        claims: Additional custom claims
    """
    private_key: str
    expires_in: int = 3600
    refresh_threshold: int = 300
    issuer: Optional[str] = None
    subject: Optional[str] = None
    audience: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict)


def generate_jwt(
    private_key: str,
    expires_in: int = 3600,
    issuer: Optional[str] = None,
    subject: Optional[str] = None,
    audience: Optional[str] = None,
    claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Generate a JWT token signed with RS256.

    Args:
        private_key: PEM-encoded RSA private key string or path to key file
        expires_in: Token validity in seconds (default: 3600 = 1 hour)
        issuer: Issuer claim (iss)
        subject: Subject claim (sub)
        audience: Audience claim (aud)
        claims: Additional custom claims

    Returns:
        Signed JWT token string

    Example:
        ```python
        from owl_browser.jwt import generate_jwt

        # Generate with default options (1 hour expiry)
        token = generate_jwt('/path/to/private.pem')

        # Generate with custom options
        token = generate_jwt(
            '/path/to/private.pem',
            expires_in=7200,  # 2 hours
            issuer='my-app',
            subject='user-123',
            claims={'role': 'admin'}
        )
        ```
    """
    _check_cryptography()

    # Load private key
    key = _load_private_key(private_key)

    # Build header
    header = {
        'alg': 'RS256',
        'typ': 'JWT'
    }

    # Build payload
    now = int(time.time())
    payload: Dict[str, Any] = {
        'iat': now,
        'exp': now + expires_in
    }

    if issuer:
        payload['iss'] = issuer
    if subject:
        payload['sub'] = subject
    if audience:
        payload['aud'] = audience
    if claims:
        payload.update(claims)

    # Encode header and payload
    header_b64 = _base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    signing_input = f'{header_b64}.{payload_b64}'

    # Sign
    signature = _sign_rs256(signing_input, key)
    signature_b64 = _base64url_encode(signature)

    return f'{signing_input}.{signature_b64}'


def decode_jwt(token: str) -> Dict[str, Any]:
    """
    Decode a JWT token without verifying the signature.
    Useful for debugging or inspecting token contents.

    Args:
        token: JWT token string

    Returns:
        Dict with 'header' and 'payload' keys

    Example:
        ```python
        result = decode_jwt(token)
        print('Token expires at:', result['payload']['exp'])
        ```
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format: expected 3 parts separated by dots')

    header_b64, payload_b64, _ = parts

    try:
        header = json.loads(_base64url_decode(header_b64).decode('utf-8'))
        payload = json.loads(_base64url_decode(payload_b64).decode('utf-8'))
        return {'header': header, 'payload': payload}
    except Exception as e:
        raise ValueError(f'Failed to decode JWT: {e}')


def is_jwt_expired(token: str, clock_skew: int = 60) -> bool:
    """
    Check if a JWT token is expired.

    Args:
        token: JWT token string
        clock_skew: Allowed clock skew in seconds (default: 60)

    Returns:
        True if the token is expired
    """
    try:
        result = decode_jwt(token)
        exp = result['payload'].get('exp')
        if exp is None:
            return False  # No expiration claim
        now = int(time.time())
        return exp < now - clock_skew
    except Exception:
        return True  # Treat invalid tokens as expired


def get_jwt_remaining_time(token: str) -> int:
    """
    Get the remaining validity time of a JWT token in seconds.

    Args:
        token: JWT token string

    Returns:
        Remaining time in seconds, or -1 if expired/invalid
    """
    try:
        result = decode_jwt(token)
        exp = result['payload'].get('exp')
        if exp is None:
            return -1  # No expiration claim
        now = int(time.time())
        remaining = exp - now
        return remaining if remaining > 0 else -1
    except Exception:
        return -1


class JWTManager:
    """
    JWT manager for automatic token generation and refresh.

    This class handles token generation and automatic refresh before expiration,
    making it easy to maintain a valid token for long-running operations.

    Example:
        ```python
        from owl_browser.jwt import JWTManager

        jwt_manager = JWTManager(
            '/path/to/private.pem',
            expires_in=3600,
            refresh_threshold=300,  # Refresh 5 minutes before expiry
            issuer='my-app'
        )

        # Get a valid token (auto-refreshes if needed)
        token = jwt_manager.get_token()
        ```
    """

    def __init__(
        self,
        private_key: str,
        expires_in: int = 3600,
        refresh_threshold: int = 300,
        issuer: Optional[str] = None,
        subject: Optional[str] = None,
        audience: Optional[str] = None,
        claims: Optional[Dict[str, Any]] = None
    ):
        """
        Create a new JWTManager.

        Args:
            private_key: PEM-encoded RSA private key string or path to key file
            expires_in: Token validity in seconds (default: 3600 = 1 hour)
            refresh_threshold: Seconds before expiry to refresh (default: 300)
            issuer: Issuer claim (iss)
            subject: Subject claim (sub)
            audience: Audience claim (aud)
            claims: Additional custom claims
        """
        _check_cryptography()

        # Load and store the private key
        self._private_key = _load_private_key(private_key)
        self._expires_in = expires_in
        self._refresh_threshold = refresh_threshold
        self._issuer = issuer
        self._subject = subject
        self._audience = audience
        self._claims = claims or {}
        self._current_token: Optional[str] = None

    def get_token(self) -> str:
        """
        Get a valid JWT token. Automatically generates a new token if the
        current one is expired or about to expire.

        Returns:
            Valid JWT token string
        """
        if self._current_token and not self._should_refresh():
            return self._current_token

        self._current_token = self._generate_token()
        return self._current_token

    def refresh_token(self) -> str:
        """
        Force refresh the token regardless of expiration status.

        Returns:
            New JWT token string
        """
        self._current_token = self._generate_token()
        return self._current_token

    def _generate_token(self) -> str:
        """Generate a new JWT token."""
        # Build header
        header = {
            'alg': 'RS256',
            'typ': 'JWT'
        }

        # Build payload
        now = int(time.time())
        payload: Dict[str, Any] = {
            'iat': now,
            'exp': now + self._expires_in
        }

        if self._issuer:
            payload['iss'] = self._issuer
        if self._subject:
            payload['sub'] = self._subject
        if self._audience:
            payload['aud'] = self._audience
        if self._claims:
            payload.update(self._claims)

        # Encode header and payload
        header_b64 = _base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_b64 = _base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        signing_input = f'{header_b64}.{payload_b64}'

        # Sign
        signature = _sign_rs256(signing_input, self._private_key)
        signature_b64 = _base64url_encode(signature)

        return f'{signing_input}.{signature_b64}'

    def _should_refresh(self) -> bool:
        """Check if the current token should be refreshed."""
        if not self._current_token:
            return True

        remaining = get_jwt_remaining_time(self._current_token)
        return remaining < self._refresh_threshold

    def get_remaining_time(self) -> int:
        """
        Get the remaining validity time of the current token.

        Returns:
            Remaining time in seconds, or -1 if no valid token
        """
        if not self._current_token:
            return -1
        return get_jwt_remaining_time(self._current_token)

    def clear_token(self) -> None:
        """Clear the current token (for cleanup or forced re-authentication)."""
        self._current_token = None


def generate_key_pair(key_size: int = 2048) -> tuple:
    """
    Generate a new RSA key pair for JWT signing.

    Args:
        key_size: Key size in bits (default: 2048)

    Returns:
        Tuple of (private_key_pem, public_key_pem) as strings

    Example:
        ```python
        from owl_browser.jwt import generate_key_pair

        private_key, public_key = generate_key_pair()

        # Save to files
        with open('private.pem', 'w') as f:
            f.write(private_key)
        with open('public.pem', 'w') as f:
            f.write(public_key)
        ```
    """
    _check_cryptography()

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Get public key and serialize to PEM
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem
