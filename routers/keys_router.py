"""
API Key management router.

This module handles:
- Creating new API keys
- Rolling over expired API keys
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import User
from schemas import APIKeyCreateRequest, APIKeyResponse, APIKeyRolloverRequest
from dependencies import get_current_user_from_jwt
from services.api_key_service import api_key_service


# Initialize router
router = APIRouter(prefix="/keys", tags=["API Keys"])


@router.post("/create", response_model=APIKeyResponse)
def create_api_key(
    request: APIKeyCreateRequest,
    user: User = Depends(get_current_user_from_jwt),
    db: Session = Depends(get_db)
):
    """
    Create a new API key for the authenticated user.
    
    Requires JWT authentication (Bearer token).
    Maximum 5 active keys per user.
    
    Args:
        request: API key creation request with name, permissions, and expiry
        user: Authenticated user from JWT token
        db: Database session
    
    Returns:
        APIKeyResponse: The plain API key (shown only once) and expiry datetime
    
    Raises:
        HTTPException:
            - 401 UNAUTHORIZED: No JWT token provided
            - 429 TOO_MANY_REQUESTS: User already has 5 active keys
            
    Security Note:
        The API key is shown ONLY in this response. It cannot be retrieved again.
        Users must save it immediately.
        
    Example Request:
        POST /keys/create
        Authorization: Bearer eyJ...
        {
            "name": "Production Server",
            "permissions": ["deposit", "read"],
            "expiry": "1M"
        }
        
    Example Response:
        {
            "api_key": "sk_live_abc123xyz789...",
            "expires_at": "2024-02-10T12:00:00"
        }
    """
    # Convert enum permissions to string list
    permissions = [p.value for p in request.permissions]
    
    # Create API key
    plain_key, expires_at = api_key_service.create_api_key(
        db=db,
        user=user,
        name=request.name,
        permissions=permissions,
        expiry=request.expiry.value
    )
    
    return APIKeyResponse(
        api_key=plain_key,
        expires_at=expires_at
    )


@router.post("/rollover", response_model=APIKeyResponse)
def rollover_api_key(
    request: APIKeyRolloverRequest,
    user: User = Depends(get_current_user_from_jwt),
    db: Session = Depends(get_db)
):
    """
    Rollover an expired API key with a new one (same permissions).
    
    Requires JWT authentication (Bearer token).
    The old key must be truly expired (past expires_at datetime).
    The new key will have the same permissions as the old key.
    
    Args:
        request: Rollover request with expired key ID and new expiry period
        user: Authenticated user from JWT token
        db: Database session
    
    Returns:
        APIKeyResponse: New API key (shown only once) and expiry datetime
    
    Raises:
        HTTPException:
            - 401 UNAUTHORIZED: No JWT token provided
            - 404 NOT_FOUND: Old key not found or doesn't belong to user
            - 400 BAD_REQUEST: Old key is not yet expired
            - 429 TOO_MANY_REQUESTS: User already has 5 active keys
            
    Example Request:
        POST /keys/rollover
        Authorization: Bearer eyJ...
        {
            "expired_key_id": "old-key-uuid-123",
            "expiry": "1M"
        }
        
    Example Response:
        {
            "api_key": "sk_live_new789xyz456...",
            "expires_at": "2024-02-10T12:00:00"
        }
    """
    # Rollover the key
    new_key, new_expires_at = api_key_service.rollover_api_key(
        db=db,
        user=user,
        expired_key_id=request.expired_key_id,
        new_expiry=request.expiry.value
    )
    
    return APIKeyResponse(
        api_key=new_key,
        expires_at=new_expires_at
    )