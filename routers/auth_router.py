"""
Authentication router for Google OAuth flow.

This module handles:
- Initiating Google OAuth flow
- Processing OAuth callback
- Creating users and wallets
- Issuing JWT tokens
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException, status,Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from authlib.integrations.starlette_client import OAuth

from database import get_db
from models import User
from schemas import TokenResponse, UserResponse, AuthResponse, WalletInfo
from auth import create_access_token
from services.wallet_service import wallet_service
from config import settings


# Initialize router
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Initialize OAuth
oauth = OAuth()
oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)


@router.get("/google")
async def google_login(request: Request):
    """
    Initiate Google OAuth flow.
    
    Redirects user to Google's consent screen where they can
    authorize the application to access their profile.
    
    Returns:
        RedirectResponse: Redirect to Google OAuth consent screen
        
    Example:
        User visits: GET /auth/google
        User is redirected to: https://accounts.google.com/o/oauth2/v2/auth?...
    """
    redirect_uri = settings.GOOGLE_REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)



@router.get("/google/callback", response_model=AuthResponse)
async def google_callback(request: Request, db: Session = Depends(get_db)):
    """
    Handle Google OAuth callback.
    
    This endpoint receives the authorization code from Google,
    exchanges it for user info, creates/updates the user account,
    creates a wallet if new user, and returns a JWT token with user data.
    
    Args:
        code: Authorization code from Google (query parameter)
        db: Database session
    
    Returns:
        AuthResponse: JWT access token and complete user information including wallet
    
    Raises:
        HTTPException:
            - 400 BAD_REQUEST: Failed to fetch user info from Google
            - 500 INTERNAL_SERVER_ERROR: Other errors
            
    Flow:
        1. Exchange code for token with Google
        2. Fetch user info from Google
        3. Find or create user in database
        4. Create wallet for new users
        5. Generate JWT token
        6. Return token with user and wallet data
        
    Example:
        Google redirects to: GET /auth/google/callback?code=abc123
        Response: {
            "user": {
                "id": "...",
                "email": "user@example.com",
                "full_name": "John Doe",
                "wallet": {
                    "id": "...",
                    "wallet_number": "1234567890123",
                    "balance": 0,
                    "created_at": "..."
                }
            },
            "accessToken": "eyJ...",
            "tokenType": "bearer"
        }
    """
    try:
        # Exchange authorization code for token
        token = await oauth.google.authorize_access_token(request)
        
        # Fetch user info from Google
        userinfo = token.get('userinfo')
        if not userinfo:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to fetch user info from Google"
            )
        
        # Extract user data
        google_id = userinfo.get('sub')  # Google's unique user ID
        email = userinfo.get('email')
        full_name = userinfo.get('name')
        
        # Find or create user
        user = db.query(User).filter(User.google_id == google_id).first()
        
        if not user:
            # Create new user
            user = User(
                id=str(uuid.uuid4()),
                google_id=google_id,
                email=email,
                full_name=full_name
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            
            # CRITICAL: Create wallet for new user
            wallet_service.create_wallet(db, user)
            db.refresh(user)
        
        # Generate JWT token
        access_token = create_access_token(data={"sub": user.id})
        
        # Prepare wallet info
        wallet_info = None
        if user.wallet:
            wallet_info = WalletInfo(
                id=user.wallet.id,
                wallet_number=user.wallet.wallet_number,
                balance=user.wallet.balance,
                created_at=user.wallet.created_at
            )
        
        # Prepare user response
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            wallet=wallet_info
        )
        
        return AuthResponse(
            user=user_response,
            access_token=access_token,
            token_type="bearer"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: {str(e)}"
        )