"""
Authentication utilities for JWT tokens and API keys.

This module provides functions for:
- JWT token creation and validation
- API key generation and hashing
- Expiry period conversion
- Paystack webhook signature verification
"""

import secrets
import hashlib
import base64
import hmac
from datetime import datetime, timedelta
from typing import Dict
from jose import JWTError, jwt
from fastapi import HTTPException, status
from config import settings


# ============================================================================
# JWT Functions
# ============================================================================

def create_access_token(data: Dict) -> str:
    """
    Create a JWT access token with expiration.
    
    Args:
        data: Dictionary containing claims to encode in the token.
              Must include 'sub' key with user_id as value.
              Example: {"sub": "user-uuid-123"}
    
    Returns:
        str: Encoded JWT token string
        
    Example:
        >>> token = create_access_token({"sub": "user-123"})
        >>> print(token)
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    """
    to_encode = data.copy()
    
    # Add expiration time to the token
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
    to_encode.update({"exp": expire})
    
    # Encode the token
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    
    return encoded_jwt


def decode_access_token(token: str) -> Dict:
    """
    Decode and validate a JWT access token.
    
    Args:
        token: JWT token string to decode
    
    Returns:
        dict: Decoded token payload containing claims
              Example: {"sub": "user-123", "exp": 1234567890}
    
    Raises:
        HTTPException: 401 UNAUTHORIZED if token is invalid or expired
        
    Example:
        >>> payload = decode_access_token(token)
        >>> user_id = payload.get("sub")
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ============================================================================
# API Key Functions
# ============================================================================

def generate_api_key() -> str:
    """
    Generate a secure random API key with prefix.
    
    Returns:
        str: API key string with format: "{prefix}{random_string}"
             Example: "sk_live_abc123xyz789..."
             
    The key is 32 bytes of random data, URL-safe base64 encoded,
    prefixed with the configured API_KEY_PREFIX.
   
    """
    random_part = secrets.token_urlsafe(32)
    return f"{settings.API_KEY_PREFIX}{random_part}"


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for secure storage using SHA256.
    
    Args:
        api_key: Plain text API key to hash
    
    Returns:
        str: Hexadecimal string of the SHA256 hash
        
    Security Note: Never store plain API keys in the database.
    Only store the hash and compare hashes during authentication.
    
    Example:
        >>> plain_key = "sk_live_abc123"
        >>> hashed = hash_api_key(plain_key)
        >>> print(hashed)
        'a1b2c3d4e5f6...'
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


def convert_expiry_to_datetime(expiry: str) -> datetime:
    """
    Convert expiry period string to future datetime.
    
    Args:
        expiry: Expiry period string. Valid values:
                - "1H": 1 hour from now
                - "1D": 1 day from now
                - "1M": 30 days from now
                - "1Y": 365 days from now
    
    Returns:
        datetime: Future datetime object representing expiry time
    
    Raises:
        ValueError: If expiry string is not one of the valid values
        
    Example:
        >>> expiry_time = convert_expiry_to_datetime("1D")
        >>> print(expiry_time)
        datetime.datetime(2024, 1, 11, 12, 0, 0)
    """
    now = datetime.utcnow()
    
    expiry_map = {
        "1H": timedelta(hours=1),
        "1D": timedelta(days=1),
        "1M": timedelta(days=30),
        "1Y": timedelta(days=365),
    }
    
    if expiry not in expiry_map:
        raise ValueError(f"Invalid expiry period: {expiry}. Must be one of: 1H, 1D, 1M, 1Y")
    
    return now + expiry_map[expiry]


# ============================================================================
# Paystack Webhook Security
# ============================================================================

    """
    Verify Paystack webhook signature for security.
    
    Args:
        payload: Raw request body as bytes (must be exact bytes received)
        signature: Value from 'x-paystack-signature' header
    
    Returns:
        bool: True if signature is valid, False otherwise
        
    Security Note: Always verify webhook signatures to ensure requests
    are actually from Paystack and haven't been tampered with.
    
    The signature is an HMAC-SHA512 hash of the payload using the
    PAYSTACK_WEBHOOK_SECRET as the key.
    
    Example:
        >>> is_valid = verify_paystack_signature(
        ...     request_body,
        ...     request.headers.get("x-paystack-signature")
        ... )
        >>> if not is_valid:
        ...     raise HTTPException(401, "Invalid signature")
    """


def verify_paystack_signature(payload: bytes, signature: str) -> bool:
    """
    Verify Paystack webhook signature (hex-encoded HMAC-SHA512).

    Args:
        payload: Raw request body as bytes.
        signature: Value from 'x-paystack-signature' header.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    hash_obj = hmac.new(
        settings.PAYSTACK_WEBHOOK_SECRET.encode('utf-8'),
        msg=payload,
        digestmod=hashlib.sha512
    )

    # Use hex digest (Paystack sends hex string)
    expected_signature = hash_obj.hexdigest()

    return hmac.compare_digest(expected_signature, signature)
