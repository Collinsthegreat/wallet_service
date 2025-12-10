"""
Wallet business logic service.

This module handles all wallet operations including:
- Wallet creation and retrieval
- Deposit processing (with idempotency)
- Fund transfers (atomic transactions)
"""

import random
import uuid
from typing import Tuple
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status

from models import User, Wallet, Transaction, TransactionType, TransactionStatus


class WalletService:
    """Service class containing wallet business logic."""
    
    @staticmethod
    def generate_wallet_number() -> str:
        """
        Generate a random 13-digit wallet number.
        
        Returns:
            str: 13-digit wallet number as string
            
        Example:
            >>> wallet_num = WalletService.generate_wallet_number()
            >>> print(wallet_num)
            '1234567890123'
            >>> len(wallet_num)
            13
        """
        # Generate random 13-digit number
        # Range: 1000000000000 to 9999999999999
        return str(random.randint(1000000000000, 9999999999999))
    
    @staticmethod
    def create_wallet(db: Session, user: User) -> Wallet:
        """
        Create a new wallet for a user.
        
        If wallet already exists, returns the existing wallet.
        Generates a unique 13-digit wallet number.
        
        Args:
            db: Database session
            user: User object to create wallet for
        
        Returns:
            Wallet: The created or existing wallet object
            
        Example:
            >>> wallet = WalletService.create_wallet(db, user)
            >>> print(wallet.wallet_number)
            '1234567890123'
            >>> print(wallet.balance)
            0.0
        """
        # Check if wallet already exists
        existing_wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
        if existing_wallet:
            return existing_wallet
        
        # Generate unique wallet number
        while True:
            wallet_number = WalletService.generate_wallet_number()
            # Check if this number is already in use
            exists = db.query(Wallet).filter(Wallet.wallet_number == wallet_number).first()
            if not exists:
                break
        
        # Create new wallet
        wallet = Wallet(
            id=str(uuid.uuid4()),
            user_id=user.id,
            wallet_number=wallet_number,
            balance=0  # Initialize balance to 0 kobo
        )
        
        db.add(wallet)
        db.commit()
        db.refresh(wallet)
        
        return wallet
    
    @staticmethod
    def get_wallet(db: Session, user: User) -> Wallet:
        """
        Get user's wallet, creating it if it doesn't exist.
        
        Args:
            db: Database session
            user: User object
        
        Returns:
            Wallet: The user's wallet object
            
        Example:
            >>> wallet = WalletService.get_wallet(db, user)
            >>> print(wallet.balance)
            0.0
        """
        wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
        if not wallet:
            wallet = WalletService.create_wallet(db, user)
        return wallet
    
    @staticmethod
    def create_pending_deposit(
        db: Session,
        wallet: Wallet,
        amount: int,
        reference: str
    ) -> Transaction:
        """
        Create a PENDING deposit transaction.
        
        This transaction will be updated to SUCCESS by the webhook.
        Checks for duplicate references to prevent re-processing.
        
        Args:
            db: Database session
            wallet: Wallet object to deposit into
            amount: Amount in kobo
            reference: Unique transaction reference
        
        Returns:
            Transaction: Created transaction with status=PENDING
        
        Raises:
            HTTPException: 409 CONFLICT if reference already exists
            
        Example:
            >>> transaction = WalletService.create_pending_deposit(
            ...     db, wallet, 50000, "DEP-unique-123"
            ... )
            >>> print(transaction.status)
            TransactionStatus.PENDING
        """
        # Check for duplicate reference
        existing = db.query(Transaction).filter(Transaction.reference == reference).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Transaction with this reference already exists"
            )
        
        # Create pending transaction
        transaction = Transaction(
            id=str(uuid.uuid4()),
            wallet_id=wallet.id,
            reference=reference,
            type=TransactionType.DEPOSIT,
            amount=amount,
            status=TransactionStatus.PENDING,
            paystack_reference=reference
        )
        
        db.add(transaction)
        db.commit()
        db.refresh(transaction)
        
        return transaction
    
    @staticmethod
    def process_webhook_deposit(
        db: Session,
        reference: str,
        status_str: str,
        amount: int
    ) -> bool:
        """
        Process deposit webhook and credit wallet (IDEMPOTENT).
        
        CRITICAL: This is the ONLY method that credits wallets for deposits.
        Must be idempotent - safe to call multiple times with same reference.
        
        Uses row locking (.with_for_update()) to prevent race conditions.
        Only processes transactions that are still PENDING.
        
        Args:
            db: Database session
            reference: Transaction reference from webhook
            status_str: Status string ("success" or "failed")
            amount: Amount in kobo
        
        Returns:
            bool: True if transaction was processed, False if already processed
        
        Raises:
            HTTPException: 404 NOT_FOUND if transaction doesn't exist
            
        Example:
            >>> # Webhook received
            >>> processed = WalletService.process_webhook_deposit(
            ...     db, "DEP-123", "success", 50000
            ... )
            >>> if processed:
            ...     print("Wallet credited")
            >>> else:
            ...     print("Already processed")
        """
        # Lock the transaction row for update
        transaction = (
            db.query(Transaction)
            .filter(Transaction.reference == reference)
            .with_for_update()
            .first()
        )
        
        if not transaction:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Transaction not found"
            )
        
        # Check if already processed (idempotency)
        if transaction.status != TransactionStatus.PENDING:
            return False  # Already processed
        
        # Process based on status
        if status_str == "success":
            # Update transaction status
            transaction.status = TransactionStatus.SUCCESS
            
            # Credit the wallet (lock wallet row too)
            wallet = (
                db.query(Wallet)
                .filter(Wallet.id == transaction.wallet_id)
                .with_for_update()
                .first()
            )
            wallet.balance += amount
            
        elif status_str == "failed":
            # Mark as failed, don't credit wallet
            transaction.status = TransactionStatus.FAILED
        
        db.commit()
        return True  # Transaction was processed
    
    @staticmethod
    def transfer_funds(
        db: Session,
        sender_wallet: Wallet,
        recipient_wallet_number: str,
        amount: int
    ) -> Tuple[Transaction, Transaction]:
        """
        Transfer funds between wallets (ATOMIC operation).
        
        CRITICAL: This operation is atomic - either completes fully or rolls back.
        Locks both wallets to prevent race conditions.
        
        Creates two transactions:
        - TRANSFER_OUT for sender
        - TRANSFER_IN for recipient
        
        Args:
            db: Database session
            sender_wallet: Sender's wallet object
            recipient_wallet_number: Recipient's 13-digit wallet number
            amount: Amount to transfer in kobo
        
        Returns:
            tuple: (sender_transaction, recipient_transaction)
        
        Raises:
            HTTPException:
                - 400 BAD_REQUEST: Insufficient balance or self-transfer
                - 404 NOT_FOUND: Recipient wallet not found
                - 500 INTERNAL_SERVER_ERROR: Transaction failed
                
        Example:
            >>> sender_tx, recipient_tx = WalletService.transfer_funds(
            ...     db, sender_wallet, "1234567890123", 10000
            ... )
            >>> print(sender_tx.type)
            TransactionType.TRANSFER_OUT
            >>> print(recipient_tx.type)
            TransactionType.TRANSFER_IN
        """
        try:
            # Validate sender balance
            if sender_wallet.balance < amount:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Insufficient wallet balance"
                )
            
            # Find recipient wallet
            recipient_wallet = (
                db.query(Wallet)
                .filter(Wallet.wallet_number == recipient_wallet_number)
                .first()
            )
            
            if not recipient_wallet:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Recipient wallet not found"
                )
            
            # Prevent self-transfer
            if sender_wallet.id == recipient_wallet.id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot transfer to your own wallet"
                )
            
            # Generate unique transfer reference
            transfer_ref = f"TRF-{uuid.uuid4()}"
            
            # Lock both wallets for update (prevent race conditions)
            # Lock in consistent order to prevent deadlocks
            wallet_ids = sorted([sender_wallet.id, recipient_wallet.id])
            locked_wallets = (
                db.query(Wallet)
                .filter(Wallet.id.in_(wallet_ids))
                .with_for_update()
                .all()
            )
            
            # Get locked instances
            for wallet in locked_wallets:
                if wallet.id == sender_wallet.id:
                    sender_wallet = wallet
                elif wallet.id == recipient_wallet.id:
                    recipient_wallet = wallet
            
            # Deduct from sender
            sender_wallet.balance -= amount
            
            # Add to recipient
            recipient_wallet.balance += amount
            
            # Create sender transaction (TRANSFER_OUT)
            sender_transaction = Transaction(
                id=str(uuid.uuid4()),
                wallet_id=sender_wallet.id,
                reference=f"{transfer_ref}-OUT",
                type=TransactionType.TRANSFER_OUT,
                amount=amount,
                status=TransactionStatus.SUCCESS,
                recipient_wallet_number=recipient_wallet_number
            )
            
            # Create recipient transaction (TRANSFER_IN)
            recipient_transaction = Transaction(
                id=str(uuid.uuid4()),
                wallet_id=recipient_wallet.id,
                reference=f"{transfer_ref}-IN",
                type=TransactionType.TRANSFER_IN,
                amount=amount,
                status=TransactionStatus.SUCCESS
            )
            
            db.add(sender_transaction)
            db.add(recipient_transaction)
            
            # Commit all changes atomically
            db.commit()
            
            db.refresh(sender_transaction)
            db.refresh(recipient_transaction)
            
            return (sender_transaction, recipient_transaction)
            
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            db.rollback()
            raise
        except Exception as e:
            # Rollback on any error
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Transfer failed: {str(e)}"
            )


# Singleton instance
wallet_service = WalletService()