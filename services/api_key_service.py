"""
API Key management service.

This module handles:
- API key creation (with 5-key limit enforcement)
- API key rollover (for expired keys)
"""

import json
import uuid
from datetime import datetime
from typing import Tuple, List
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from models import User, APIKey
from auth import generate_api_key, hash_api_key, convert_expiry_to_datetime
from config import settings


class APIKeyService:
    """Service class for API key management."""
    
    @staticmethod
    def create_api_key(
        db: Session,
        user: User,
        name: str,
        permissions: List[str],
        expiry: str
    ) -> Tuple[str, datetime]:
        """
        Create a new API key for a user.
        
        Enforces maximum of 5 active keys per user.
        Active keys are those that are not revoked AND not expired.
        
        Args:
            db: Database session
            user: User object
            name: User-friendly name for the key
            permissions: List of permission strings ["deposit", "transfer", "read"]
            expiry: Expiry period ("1H", "1D", "1M", "1Y")
        
        Returns:
            tuple: (plain_api_key, expires_at_datetime)
                   Plain key is returned ONLY here - never shown again
        
        Raises:
            HTTPException: 429 TOO_MANY_REQUESTS if user already has 5 active keys
            
        Example:
            >>> plain_key, expiry = APIKeyService.create_api_key(
            ...     db, user, "Production", ["deposit", "read"], "1M"
            ... )
            >>> print(plain_key)
            'sk_live_abc123xyz...'
            >>> # Save this key! It won't be shown again
        """
        # Check how many active keys the user has
        now = datetime.utcnow()
        active_keys_count = (
            db.query(APIKey)
            .filter(
                APIKey.user_id == user.id,
                APIKey.is_revoked == False,
                APIKey.expires_at > now
            )
            .count()
        )
        
        if active_keys_count >= settings.MAX_ACTIVE_API_KEYS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Maximum {settings.MAX_ACTIVE_API_KEYS} active API keys allowed per user"
            )
        
        # Generate plain API key
        plain_key = generate_api_key()
        
        # Hash the key for storage
        key_hash = hash_api_key(plain_key)
        
        # Convert expiry string to datetime
        expires_at = convert_expiry_to_datetime(expiry)
        
        # Create API key record
        api_key = APIKey(
            id=str(uuid.uuid4()),
            user_id=user.id,
            name=name,
            key_hash=key_hash,
            permissions=json.dumps(permissions),  # Store as JSON string
            expires_at=expires_at,
            is_revoked=False
        )
        
        db.add(api_key)
        db.commit()
        db.refresh(api_key)
        
        # Return plain key (shown only once) and expiry
        return (plain_key, expires_at)
    
    @staticmethod
    def rollover_api_key(
        db: Session,
        user: User,
        expired_key_id: str,
        new_expiry: str
    ) -> Tuple[str, datetime]:
        """
        Rollover an expired API key with same permissions.
        
        This allows users to renew expired keys without changing permissions.
        The old key must be truly expired (past expires_at).
        Still enforces the 5-key limit.
        
        Args:
            db: Database session
            user: User object
            expired_key_id: ID of the expired key to rollover
            new_expiry: Expiry period for new key ("1H", "1D", "1M", "1Y")
        
        Returns:
            tuple: (new_plain_api_key, new_expires_at_datetime)
        
        Raises:
            HTTPException:
                - 404 NOT_FOUND: Key not found or doesn't belong to user
                - 400 BAD_REQUEST: Key is not yet expired
                - 429 TOO_MANY_REQUESTS: User already has 5 active keys
                
        Example:
            >>> new_key, new_expiry = APIKeyService.rollover_api_key(
            ...     db, user, "old-key-id-123", "1M"
            ... )
            >>> print(new_key)
            'sk_live_xyz789abc...'
        """
        # Find the old key
        old_key = (
            db.query(APIKey)
            .filter(
                APIKey.id == expired_key_id,
                APIKey.user_id == user.id
            )
            .first()
        )
        
        if not old_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        # Verify the key is truly expired
        now = datetime.utcnow()
        if now <= old_key.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="API key is not yet expired. Cannot rollover."
            )
        
        # Extract old key's permissions
        old_permissions = json.loads(old_key.permissions)
        
        # Create new key with same permissions
        # This will check the 5-key limit
        return APIKeyService.create_api_key(
            db=db,
            user=user,
            name=old_key.name,  # Keep same name
            permissions=old_permissions,
            expiry=new_expiry
        )


# Singleton instance
api_key_service = APIKeyService()