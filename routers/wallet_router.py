"""
Wallet operations router.

This module handles:
- Deposit initialization (Paystack)
- Webhook processing (crediting wallets)
- Deposit status checking
- Balance retrieval
- Fund transfers
- Transaction history
"""

import uuid
from typing import List
from fastapi import APIRouter, Depends, Request, Header, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from models import User, Transaction, TransactionType
from schemas import (
    WalletDepositRequest, WalletDepositResponse, DepositStatusResponse,
    WalletBalanceResponse, WalletMeResponse, WalletTransferRequest, WalletTransferResponse,
    TransactionResponse, WebhookResponse
)
from dependencies import require_permission
from services.wallet_service import wallet_service
from services.paystack_service import paystack_service
from auth import verify_paystack_signature


# Initialize router
router = APIRouter(prefix="/wallet", tags=["Wallet"])


@router.post("/deposit", response_model=WalletDepositResponse)
async def initialize_deposit(
    request: WalletDepositRequest,
    user: User = Depends(require_permission("deposit")),
    db: Session = Depends(get_db)
):
    """
    Initialize a deposit via Paystack.
    
    Requires "deposit" permission (JWT or API key with deposit permission).
    
    Creates a PENDING transaction and returns Paystack payment URL.
    User completes payment on Paystack, then webhook credits the wallet.
    
    Args:
        request: Deposit request with amount in kobo
        user: Authenticated user
        db: Database session
    
    Returns:
        WalletDepositResponse: Transaction reference and Paystack payment URL
    
    Raises:
        HTTPException:
            - 401/403: Authentication/authorization errors
            - 409 CONFLICT: Duplicate transaction reference
            - 400/502: Paystack errors
            
    Example Request:
        POST /wallet/deposit
        Authorization: Bearer eyJ... (or x-api-key: sk_live_...)
        {
            "amount": 50000
        }
        
    Example Response:
        {
            "reference": "DEP-abc123-xyz789",
            "authorization_url": "https://checkout.paystack.com/abc123"
        }
    """
    # Get or create user's wallet
    wallet = wallet_service.get_wallet(db, user)
    
    # Generate unique reference
    reference = f"DEP-{uuid.uuid4()}"
    
    # Create pending transaction (amount already in kobo)
    wallet_service.create_pending_deposit(db, wallet, request.amount, reference)
    
    # Initialize transaction with Paystack (amount already in kobo)
    paystack_response = await paystack_service.initialize_transaction(
        email=user.email,
        amount=request.amount,  # Already in kobo
        reference=reference
    )
    
    return WalletDepositResponse(
        reference=reference,
        authorization_url=paystack_response["authorization_url"]
    )


@router.post("/paystack/webhook", response_model=WebhookResponse)
async def paystack_webhook(
    request: Request,
    x_paystack_signature: str = Header(None),
    db: Session = Depends(get_db)
):
    """
    Handle Paystack webhook events (CRITICAL - ONLY ENDPOINT THAT CREDITS WALLETS).
    
    NO AUTHENTICATION REQUIRED - Uses signature verification instead.
    This endpoint is called by Paystack when payment status changes.
    
    MUST be idempotent - Paystack may send the same event multiple times.
    Only processes 'charge.success' events.
    
    Args:
        request: FastAPI request object (for raw body)
        x_paystack_signature: Signature header from Paystack
        db: Database session
    
    Returns:
        WebhookResponse: Always returns success (even on errors)
    
    Raises:
        HTTPException: 401 UNAUTHORIZED if signature is invalid
        
    Security:
        Signature verification ensures requests are from Paystack.
        
    Important:
        - Always return 200 OK to Paystack (prevents retries)
        - Log errors for debugging but don't fail webhook
        - Idempotency prevents double-crediting
        
    Example Webhook Payload:
        {
            "event": "charge.success",
            "data": {
                "reference": "DEP-abc123",
                "status": "success",
                "amount": 50000  // in kobo
            }
        }
    """
    try:
        # Get raw request body (needed for signature verification)
        body = await request.body()
        
        # Verify signature
        if not x_paystack_signature:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Paystack signature"
            )
        
        if not verify_paystack_signature(body, x_paystack_signature):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Paystack signature"
            )
        
        # Parse JSON payload
        payload = await request.json()
        
        # Only process charge.success events
        if payload.get("event") != "charge.success":
            return WebhookResponse(status=True)
        
        # Extract data
        data = payload.get("data", {})
        reference = data.get("reference")
        status_str = data.get("status")
        amount_kobo = data.get("amount")
        
        # Process the deposit (amount already in kobo - no conversion needed)
        wallet_service.process_webhook_deposit(
            db=db,
            reference=reference,
            status_str=status_str,
            amount=amount_kobo
        )
        
        return WebhookResponse(status=True)
        
    except HTTPException:
        raise
    except Exception as e:
        # Log error but return success to Paystack
        # (prevents retries for unrecoverable errors)
        print(f"Webhook processing error: {str(e)}")
        return WebhookResponse(status=True)


@router.get("/deposit/{reference}/status", response_model=DepositStatusResponse)
def get_deposit_status(
    reference: str,
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """
    Check the status of a deposit transaction (READ-ONLY).
    
    Requires "read" permission (JWT or API key with read permission).
    
    This is for manual status checks only.
    DOES NOT CREDIT WALLET - only the webhook does that.
    
    Args:
        reference: Transaction reference (from deposit response)
        user: Authenticated user
        db: Database session
    
    Returns:
        DepositStatusResponse: Transaction reference, status, and amount
    
    Raises:
        HTTPException:
            - 401/403: Authentication/authorization errors
            - 404 NOT_FOUND: Transaction not found or doesn't belong to user
            
    Example Request:
        GET /wallet/deposit/DEP-abc123/status
        Authorization: Bearer eyJ... (or x-api-key: sk_live_...)
        
    Example Response:
        {
            "reference": "DEP-abc123",
            "status": "success",
            "amount": 500.0
        }
    """
    # Get user's wallet
    wallet = wallet_service.get_wallet(db, user)
    
    # Find transaction
    transaction = (
        db.query(Transaction)
        .filter(
            Transaction.reference == reference,
            Transaction.wallet_id == wallet.id
        )
        .first()
    )
    
    if not transaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transaction not found"
        )
    
    return DepositStatusResponse(
        reference=transaction.reference,
        status=transaction.status.value.lower(),
        amount=transaction.amount
    )


@router.post("/deposit/{reference}/verify", response_model=DepositStatusResponse)
async def verify_deposit(
    reference: str,
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """
    Verify a deposit transaction with Paystack (MANUAL VERIFICATION ONLY).
    
    Requires "read" permission (JWT or API key with read permission).
    
    This endpoint queries Paystack directly to verify transaction status.
    IMPORTANT: This is for manual verification only - does NOT credit wallet.
    Only the webhook credits wallets.
    
    Args:
        reference: Transaction reference (from deposit response)
        user: Authenticated user
        db: Database session
    
    Returns:
        DepositStatusResponse: Transaction reference, status, and amount
    
    Raises:
        HTTPException:
            - 401/403: Authentication/authorization errors
            - 404 NOT_FOUND: Transaction not found in Paystack
            - 502 BAD_GATEWAY: Paystack API error
            
    Example Request:
        POST /wallet/deposit/DEP-abc123/verify
        Authorization: Bearer eyJ... (or x-api-key: sk_live_...)
        
    Example Response:
        {
            "reference": "DEP-abc123",
            "status": "success",
            "amount": 50000
        }
    """
    # Get user's wallet
    wallet = wallet_service.get_wallet(db, user)
    
    # Find transaction in local database
    transaction = (
        db.query(Transaction)
        .filter(
            Transaction.reference == reference,
            Transaction.wallet_id == wallet.id
        )
        .first()
    )
    
    if not transaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transaction not found"
        )
    
    # Verify with Paystack
    paystack_data = await paystack_service.verify_transaction(reference)
    
    return DepositStatusResponse(
        reference=reference,
        status=paystack_data.get("status", "pending"),
        amount=paystack_data.get("amount", 0)
    )


@router.get("/balance", response_model=WalletBalanceResponse)
def get_balance(
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """
    Get current wallet balance.
    
    Requires "read" permission (JWT or API key with read permission).
    
    Args:
        user: Authenticated user
        db: Database session
    
    Returns:
        WalletBalanceResponse: Current balance in Naira
        
    Example Request:
        GET /wallet/balance
        Authorization: Bearer eyJ... (or x-api-key: sk_live_...)
        
    Example Response:
        {
            "balance": 1250.50
        }
    """
    wallet = wallet_service.get_wallet(db, user)
    return WalletBalanceResponse(balance=wallet.balance)

@router.get("/me", response_model=WalletMeResponse)
def get_my_wallet(
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """
    Return authenticated user's wallet details.
    Includes wallet ID, wallet number, balance, and created_at.
    """
    wallet = wallet_service.get_wallet(db, user)
    return wallet


@router.post("/transfer", response_model=WalletTransferResponse)
def transfer_funds(
    request: WalletTransferRequest,
    user: User = Depends(require_permission("transfer")),
    db: Session = Depends(get_db)
):
    """
    Transfer funds to another wallet.
    
    Requires "transfer" permission (JWT or API key with transfer permission).
    
    Transfer is ATOMIC - either completes fully or rolls back completely.
    Creates two transactions: TRANSFER_OUT (sender) and TRANSFER_IN (recipient).
    
    Args:
        request: Transfer request with recipient wallet number and amount
        user: Authenticated user
        db: Database session
    
    Returns:
        WalletTransferResponse: Success message
    
    Raises:
        HTTPException:
            - 401/403: Authentication/authorization errors
            - 400 BAD_REQUEST: Insufficient balance or self-transfer
            - 404 NOT_FOUND: Recipient wallet not found
            - 500 INTERNAL_SERVER_ERROR: Transaction failed
            
    Example Request:
        POST /wallet/transfer
        Authorization: Bearer eyJ... (or x-api-key: sk_live_...)
        {
            "wallet_number": "1234567890123",
            "amount": 10000
        }
        
    Example Response:
        {
            "status": "success",
            "message": "Successfully transferred 10000 kobo to wallet 1234567890123"
        }
    """
    # Get sender's wallet
    sender_wallet = wallet_service.get_wallet(db, user)
    
    # Perform transfer (amount already in kobo)
    wallet_service.transfer_funds(
        db=db,
        sender_wallet=sender_wallet,
        recipient_wallet_number=request.wallet_number,
        amount=request.amount
    )
    
    return WalletTransferResponse(
        status="success",
        message=f"Successfully transferred {request.amount} kobo to wallet {request.wallet_number}"
    )


@router.get("/transactions", response_model=List[TransactionResponse])
def get_transaction_history(
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """
    Get transaction history for user's wallet.
    
    Requires "read" permission (JWT or API key with read permission).
    
    Returns all transactions (deposits, transfers in, transfers out)
    ordered by most recent first.
    
    Args:
        user: Authenticated user
        db: Database session
    
    Returns:
        List[TransactionResponse]: List of transactions
        
    Example Request:
        GET /wallet/transactions
        Authorization: Bearer eyJ... (or x-api-key: sk_live_...)
        
    Example Response:
        [
            {
                "id": "txn-123",
                "type": "DEPOSIT",
                "amount": 50000,
                "status": "SUCCESS",
                "reference": "DEP-abc123",
                "recipient_wallet_number": null,
                "created_at": "2024-01-10T12:00:00"
            },
            {
                "id": "txn-456",
                "type": "TRANSFER_OUT",
                "amount": 10000,
                "status": "SUCCESS",
                "reference": "TRF-xyz789-OUT",
                "recipient_wallet_number": "1234567890123",
                "created_at": "2024-01-09T15:30:00"
            }
        ]
    """
    # Get user's wallet
    wallet = wallet_service.get_wallet(db, user)
    
    # Query all transactions for this wallet
    transactions = (
        db.query(Transaction)
        .filter(Transaction.wallet_id == wallet.id)
        .order_by(Transaction.created_at.desc())
        .all()
    )
    
    return transactions