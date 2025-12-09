"""
SQLAlchemy ORM models for the Wallet Service.

This module defines all database tables and their relationships:
- User: User accounts from Google OAuth
- Wallet: One wallet per user for storing balance
- Transaction: All financial transactions (deposits, transfers)
- APIKey: API keys for programmatic access
"""

import enum
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, Boolean, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.orm import relationship
from database import Base
import uuid


# Enums for Transaction model
class TransactionType(enum.Enum):
    """Types of transactions that can occur in the system."""
    DEPOSIT = "DEPOSIT"  # Funds added via Paystack
    TRANSFER_IN = "TRANSFER_IN"  # Funds received from another wallet
    TRANSFER_OUT = "TRANSFER_OUT"  # Funds sent to another wallet


class TransactionStatus(enum.Enum):
    """Status of a transaction throughout its lifecycle."""
    PENDING = "PENDING"  # Transaction initiated but not confirmed
    SUCCESS = "SUCCESS"  # Transaction completed successfully
    FAILED = "FAILED"  # Transaction failed


class User(Base):
    """
    User account model representing authenticated users.
    
    Users authenticate via Google OAuth. Each user can have:
    - One wallet for storing funds
    - Multiple API keys (up to 5 active) for programmatic access
    """
    __tablename__ = "users"
    
    # Primary identifier - UUID for better security than sequential IDs
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Email from Google OAuth - used for Paystack transactions
    email = Column(String, unique=True, nullable=False, index=True)
    
    # Google's unique identifier for this user
    google_id = Column(String, unique=True, nullable=False)
    
    # User's full name from Google profile (optional)
    full_name = Column(String, nullable=True)
    
    # Account creation timestamp
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    wallet = relationship("Wallet", back_populates="user", uselist=False, cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")


class Wallet(Base):
    """
    Wallet model for storing user balances.
    
    Design decision: One wallet per user for simplicity.
    Each wallet has a unique 13-digit wallet number for transfers.
    """
    __tablename__ = "wallets"
    
    # Primary identifier
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Foreign key to user - one-to-one relationship
    user_id = Column(String, ForeignKey("users.id"), unique=True, nullable=False)
    
    # 13-digit unique identifier for transfers between wallets
    wallet_number = Column(String(13), unique=True, nullable=False, index=True)
    
    # Current balance in Naira - default 0.0, never NULL
    balance = Column(Float, default=0.0, nullable=False)
    
    # Timestamps for audit trail
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="wallet")
    transactions = relationship("Transaction", back_populates="wallet", cascade="all, delete-orphan")


class Transaction(Base):
    """
    Transaction model for all financial operations.
    
    Tracks three types of transactions:
    - DEPOSIT: Funds added via Paystack (reference from Paystack)
    - TRANSFER_IN: Funds received from another wallet
    - TRANSFER_OUT: Funds sent to another wallet
    
    Critical: reference field ensures idempotency - prevents duplicate processing.
    """
    __tablename__ = "transactions"
    
    # Primary identifier
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Foreign key to wallet - many transactions per wallet
    wallet_id = Column(String, ForeignKey("wallets.id"), nullable=False, index=True)
    
    # Unique reference for idempotency - CRITICAL for preventing duplicates
    reference = Column(String, unique=True, nullable=False, index=True)
    
    # Type of transaction (DEPOSIT, TRANSFER_IN, TRANSFER_OUT)
    type = Column(SQLEnum(TransactionType), nullable=False)
    
    # Amount in Naira
    amount = Column(Float, nullable=False)
    
    # Current status of the transaction
    status = Column(SQLEnum(TransactionStatus), default=TransactionStatus.PENDING, nullable=False)
    
    # For transfers: the recipient's wallet number (NULL for deposits)
    recipient_wallet_number = Column(String(13), nullable=True)
    
    # For deposits: Paystack's transaction reference (NULL for transfers)
    paystack_reference = Column(String, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    wallet = relationship("Wallet", back_populates="transactions")
    
    # Composite index for efficient queries on wallet history
    __table_args__ = (
        Index('ix_transactions_wallet_created', 'wallet_id', 'created_at'),
    )


class APIKey(Base):
    """
    API Key model for programmatic access to the wallet service.
    
    Users can create up to 5 active API keys. Each key has:
    - Permissions: deposit, transfer, read (JSON array as string)
    - Expiry: 1H, 1D, 1M, or 1Y from creation
    - Revocation: can be manually revoked by user
    
    Security: Only the hash is stored, never the plain key.
    The plain key is shown to the user only once at creation.
    """
    __tablename__ = "api_keys"
    
    # Primary identifier
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Foreign key to user
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    
    # User-friendly name for the key (e.g., "Production Server", "Mobile App")
    name = Column(String(100), nullable=False)
    
    # SHA256 hash of the API key - NEVER store plain keys
    key_hash = Column(String, unique=True, nullable=False)
    
    # JSON array of permissions: ["deposit", "transfer", "read"]
    permissions = Column(String, nullable=False)
    
    # Expiry datetime - checked on every request
    expires_at = Column(DateTime, nullable=False, index=True)
    
    # Manual revocation flag - user can revoke keys before expiry
    is_revoked = Column(Boolean, default=False, nullable=False)
    
    # Creation timestamp
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    # Composite index for efficient active key queries
    __table_args__ = (
        Index('ix_api_keys_user_revoked_expiry', 'user_id', 'is_revoked', 'expires_at'),
    )