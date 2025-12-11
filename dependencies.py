"""
FastAPI dependency functions for authentication and authorization.

This module provides dependency functions that can be used in route handlers
to authenticate users via JWT or API keys and check permissions.
"""

import json
from datetime import datetime
from typing import Optional, Tuple, List, Callable
from fastapi import Depends, HTTPException, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database import get_db
from models import User, APIKey
from auth import decode_access_token, hash_api_key


# Security scheme for JWT authentication
security = HTTPBearer(auto_error=False)


# ============================================================================
# JWT Authentication
# ============================================================================

async def get_current_user_from_jwt(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Extract and validate user from JWT Bearer token.
    
    Args:
        credentials: HTTP Authorization credentials from request header
        db: Database session
    
    Returns:
        User: User object if JWT is valid
        None: If no JWT provided
    
    Raises:
        HTTPException: 401 UNAUTHORIZED if JWT is invalid or expired
        
    Usage:
        @app.get("/protected")
        def protected_route(user: User = Depends(get_current_user_from_jwt)):
            return {"user_id": user.id}
    """
    if not credentials:
        return None
    
    # Decode the JWT token
    payload = decode_access_token(credentials.credentials)
    user_id = payload.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    # Fetch user from database
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    return user


# ============================================================================
# API Key Authentication
# ============================================================================

async def get_current_user_from_api_key(
    x_api_key: Optional[str] = Header(None, include_in_schema=False),
    db: Session = Depends(get_db)
) -> Optional[Tuple[User, List[str]]]:
    """
    Extract and validate user from API key header.
    
    Args:
        x_api_key: API key from 'x-api-key' header
        db: Database session
    
    Returns:
        tuple: (User object, list of permissions) if API key is valid
        None: If no API key provided
    
    Raises:
        HTTPException: 401 UNAUTHORIZED if API key is:
            - Invalid (not found in database)
            - Revoked (manually disabled)
            - Expired (past expires_at datetime)
            
    Usage:
        @app.get("/api-protected")
        def api_protected_route(
            user_data: Tuple[User, List[str]] = Depends(get_current_user_from_api_key)
        ):
            user, permissions = user_data
            return {"user_id": user.id, "permissions": permissions}
    """
    if not x_api_key:
        return None
    
    # Hash the provided key to compare with stored hash
    key_hash = hash_api_key(x_api_key)
    
    # Find the API key in database
    api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Check if key is revoked
    if api_key.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked"
        )
    
    # Check if key is expired
    if datetime.utcnow() > api_key.expires_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired"
        )
    
    # Get the user associated with this key
    user = db.query(User).filter(User.id == api_key.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Parse permissions from JSON string
    permissions = json.loads(api_key.permissions)
    
    return (user, permissions)


# ============================================================================
# Combined Authentication
# ============================================================================

async def get_authenticated_user(
    jwt_user: Optional[User] = Depends(get_current_user_from_jwt),
    api_key_data: Optional[Tuple[User, List[str]]] = Depends(get_current_user_from_api_key),
    db: Session = Depends(get_db)
) -> Tuple[User, Optional[List[str]]]:
    """
    Authenticate user via JWT or API key (tries JWT first, then API key).
    
    Args:
        jwt_user: User from JWT token (None if no JWT provided)
        api_key_data: Tuple of (User, permissions) from API key (None if no key)
        db: Database session
    
    Returns:
        tuple: (User, None) if authenticated via JWT (all permissions)
               (User, permissions_list) if authenticated via API key
    
    Raises:
        HTTPException: 401 UNAUTHORIZED if neither JWT nor API key provided
        
    Usage:
        @app.get("/flexible-auth")
        def flexible_route(
            auth_data: Tuple[User, Optional[List[str]]] = Depends(get_authenticated_user)
        ):
            user, permissions = auth_data
            if permissions is None:
                # JWT user - has all permissions
                return {"auth": "JWT", "user_id": user.id}
            else:
                # API key user - check permissions
                return {"auth": "API_KEY", "user_id": user.id, "permissions": permissions}
    """
    # Try JWT first (has priority)
    if jwt_user:
        return (jwt_user, None)
    
    # Try API key
    if api_key_data:
        return api_key_data
    
    # No authentication provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide either JWT token or API key"
    )


# ============================================================================
# Permission Checker
# ============================================================================

def require_permission(required_permission: str) -> Callable:
    """
    Factory function that creates a dependency to check for a specific permission.
    
    Args:
        required_permission: Permission string to require ("deposit", "transfer", "read")
    
    Returns:
        Callable: Dependency function that checks the permission
    
    Raises:
        HTTPException: 403 FORBIDDEN if API key lacks the required permission
        
    Usage:
        @app.post("/wallet/transfer")
        def transfer(
            user: User = Depends(require_permission("transfer")),
            db: Session = Depends(get_db)
        ):
            # user is guaranteed to have "transfer" permission
            return {"message": "Transfer successful"}
            
    Note:
        - JWT users always pass (they have all permissions)
        - API key users must have the specific permission in their key
    """
    async def permission_checker(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
        x_api_key: Optional[str] = Header(None), alias="x-api-key"),  # include_in_schema removed
        db: Session = Depends(get_db)
    ) -> User:
        # Try JWT first
        if credentials:
            try:
                payload = decode_access_token(credentials.credentials)
                user_id = payload.get("sub")
                
                if not user_id:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired token"
                    )
                
                user = db.query(User).filter(User.id == user_id).first()
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired token"
                    )
                
                # JWT users have all permissions
                return user
                
            except HTTPException:
                raise
        
        # Try API key
        if x_api_key:
            key_hash = hash_api_key(x_api_key)
            api_key = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
            
            if not api_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API key"
                )
            
            if api_key.is_revoked:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key has been revoked"
                )
            
            if datetime.utcnow() > api_key.expires_at:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key has expired"
                )
            
            user = db.query(User).filter(User.id == api_key.user_id).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API key"
                )
            
            # Check permission for API key
            permissions = json.loads(api_key.permissions)
            if required_permission not in permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key lacks required permission: {required_permission}"
                )
            
            return user
        
        # Neither JWT nor API key provided
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide either JWT token or API key"
        )
    
    return permission_checker
