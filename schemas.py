"""
Pydantic schemas for request validation and response serialization.

This module defines all data models for API requests and responses with
comprehensive field validation to ensure data integrity.
"""

from pydantic import BaseModel, Field, field_validator
from typing import List, Literal, Optional
from datetime import datetime
from enum import Enum


# ============================================================================
# Authentication Schemas
# ============================================================================

class TokenResponse(BaseModel):
    """Response model for OAuth authentication containing JWT token."""
    access_token: str = Field(..., description="JWT access token for authentication", alias="accessToken")
    accessToken: str = Field(..., alias="access_token")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')", alias="tokenType")
    
    model_config = {"populate_by_name": True}


class WalletInfo(BaseModel):
    """Wallet information in user response."""
    id: str = Field(..., description="Wallet ID")
    wallet_number: str = Field(..., description="13-digit wallet number")
    balance: int = Field(..., description="Wallet balance in kobo")
    created_at: datetime = Field(..., description="Wallet creation date")
    
    model_config = {"from_attributes": True}


class UserResponse(BaseModel):
    """Response model for user information."""
    id: str = Field(..., description="Unique user identifier")
    email: str = Field(..., description="User's email address from Google")
    full_name: Optional[str] = Field(None, description="User's full name from Google profile")
    wallet: Optional[WalletInfo] = Field(None, description="User's wallet information")
    
    model_config = {"from_attributes": True}


class AuthResponse(BaseModel):
    """Complete authentication response with user data."""
    user: UserResponse = Field(..., description="User information")
    access_token: str = Field(..., description="JWT access token", alias="accessToken")
    token_type: str = Field(default="bearer", description="Token type", alias="tokenType")
    
    model_config = {"populate_by_name": True}


# ============================================================================
# API Key Schemas
# ============================================================================

class ExpiryPeriod(str, Enum):
    """Enum for API key expiry periods."""
    ONE_HOUR = "1H"
    ONE_DAY = "1D"
    ONE_MONTH = "1M"
    ONE_YEAR = "1Y"


class PermissionType(str, Enum):
    """Enum for API key permissions."""
    DEPOSIT = "deposit"  # Can initialize deposits
    TRANSFER = "transfer"  # Can transfer funds between wallets
    READ = "read"  # Can read wallet balance and transactions


class APIKeyCreateRequest(BaseModel):
    """Request model for creating a new API key."""
    name: str = Field(
        ..., 
        min_length=1, 
        max_length=100,
        description="User-friendly name for the API key (e.g., 'Production Server')"
    )
    permissions: List[PermissionType] = Field(
        ..., 
        min_length=1,
        description="List of permissions for this key (deposit, transfer, read)"
    )
    expiry: ExpiryPeriod = Field(
        ...,
        description="Expiry period for the key (1H, 1D, 1M, 1Y)"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "name": "wallet-service",
                "permissions": ["deposit", "transfer", "read"],
                "expiry": "1D",
            }
        }
    }
    
    @field_validator('permissions')
    @classmethod
    def validate_no_duplicate_permissions(cls, v: List[PermissionType]) -> List[PermissionType]:
        """Ensure no duplicate permissions in the list."""
        if len(v) != len(set(v)):
            raise ValueError("Duplicate permissions are not allowed")
        return v


class APIKeyResponse(BaseModel):
    """Response model after creating an API key - contains the plain key (shown only once)."""
    api_key: str = Field(..., description="The API key - SAVE THIS, it won't be shown again")
    expires_at: datetime = Field(..., description="When this key will expire")


class APIKeyRolloverRequest(BaseModel):
    """Request model for rolling over an expired API key."""
    expired_key_id: str = Field(..., description="ID of the expired key to rollover")
    expiry: ExpiryPeriod = Field(..., description="Expiry period for the new key")


class APIKeyListItem(BaseModel):
    """Schema for listing API keys (without showing the actual API key)."""
    id: str = Field(..., description="API key ID")
    name: str = Field(..., description="User-friendly name of the API key")
    permissions: List[str] = Field(..., description="List of permissions granted to this key")
    expires_at: datetime = Field(..., description="Expiry date of the API key")
    is_revoked: bool = Field(..., description="Whether the API key has been revoked")
    created_at: datetime = Field(..., description="Date and time when the key was created")
    
    model_config = {"from_attributes": True}


# ============================================================================
# Wallet Schemas
# ============================================================================

class WalletDepositRequest(BaseModel):
    """Request model for initiating a deposit via Paystack."""
    amount: int = Field(..., gt=0, description="Amount to deposit in kobo (must be positive integer)", example=5000)
    
    @field_validator('amount')
    @classmethod
    def validate_amount_reasonable(cls, v: int) -> int:
        """Ensure amount is reasonable (less than 100M kobo = 1M Naira)."""
        if v >= 100_000_000:
            raise ValueError("Amount must be less than 100,000,000 kobo (1,000,000 Naira)")
        return v


class WalletDepositResponse(BaseModel):
    """Response model after initiating a deposit - contains Paystack payment URL."""
    reference: str = Field(..., description="Unique transaction reference")
    authorization_url: str = Field(..., description="Paystack URL to complete payment")


class DepositStatusResponse(BaseModel):
    """Response model for checking deposit status."""
    reference: str = Field(..., description="Transaction reference")
    status: Literal["success", "failed", "pending"] = Field(..., description="Current transaction status")
    amount: int = Field(..., description="Transaction amount in kobo")


class WalletBalanceResponse(BaseModel):
    """Response model for wallet balance."""
    balance: int = Field(..., description="Current wallet balance in kobo")


class WalletMeResponse(BaseModel):
    """Response model for retrieving the authenticated user's wallet information."""
    id: str = Field(..., description="Wallet ID")
    wallet_number: str = Field(..., description="13-digit wallet number")
    balance: int = Field(..., description="Current wallet balance in kobo")
    created_at: datetime = Field(..., description="Date and time when the wallet was created")

    model_config = {"from_attributes": True}


class WalletTransferRequest(BaseModel):
    """Request model for transferring funds between wallets."""
    wallet_number: str = Field(
        ..., 
        min_length=13, 
        max_length=13,
        description="Recipient's 13-digit wallet number",
        example="4566674598456"
    )
    amount: int = Field(..., gt=0, description="Amount to transfer in kobo (must be positive integer)", example=10000)
    
    @field_validator('wallet_number')
    @classmethod
    def validate_wallet_number_format(cls, v: str) -> str:
        """Ensure wallet number is exactly 13 digits."""
        if not v.isdigit():
            raise ValueError("Wallet number must contain only digits")
        if len(v) != 13:
            raise ValueError("Wallet number must be exactly 13 digits")
        return v
    
    @field_validator('amount')
    @classmethod
    def validate_transfer_amount(cls, v: int) -> int:
        """Ensure transfer amount is positive and reasonable."""
        if v <= 0:
            raise ValueError("Transfer amount must be positive")
        if v >= 100_000_000:
            raise ValueError("Transfer amount must be less than 100,000,000 kobo (1,000,000 Naira)")
        return v


class WalletTransferResponse(BaseModel):
    """Response model after successful transfer."""
    status: Literal["success"] = Field(default="success", description="Transfer status")
    message: str = Field(..., description="Success message with transfer details")


class TransactionResponse(BaseModel):
    """Response model for transaction history."""
    id: str = Field(..., description="Transaction ID")
    type: str = Field(..., description="Transaction type (DEPOSIT, TRANSFER_IN, TRANSFER_OUT)")
    amount: int = Field(..., description="Transaction amount in kobo")
    status: str = Field(..., description="Transaction status (PENDING, SUCCESS, FAILED)")
    reference: str = Field(..., description="Unique transaction reference")
    recipient_wallet_number: Optional[str] = Field(None, description="Recipient wallet number (for transfers)")
    created_at: datetime = Field(..., description="When the transaction was created")
    
    model_config = {"from_attributes": True}

class PaginatedTransactionResponse(BaseModel):
    """Paginated transaction response with metadata."""
    data: List[TransactionResponse]
    meta: dict = Field(..., example={
        "total": 45,
        "page": 1,
        "limit": 20,
        "totalPages": 3
    })


class WebhookResponse(BaseModel):
    """Response model for webhook endpoint - always returns success."""
    status: bool = Field(default=True, description="Webhook processing status")
