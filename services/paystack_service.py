"""
Paystack API integration service.

This module handles all interactions with the Paystack payment gateway API,
including transaction initialization and verification.
"""

import httpx
from typing import Dict
from fastapi import HTTPException, status
from config import settings


class PaystackService:
    """
    Service class for interacting with Paystack API.
    
    Handles payment initialization and transaction verification
    using Paystack's REST API.
    """
    
    BASE_URL = "https://api.paystack.co"
    
    def __init__(self):
        """Initialize Paystack service with API credentials."""
        self.secret_key = settings.PAYSTACK_SECRET_KEY
        self.headers = {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/json"
        }
    
    async def initialize_transaction(
        self,
        email: str,
        amount: int,
        reference: str
    ) -> Dict:
        """
        Initialize a payment transaction with Paystack.
        
        Args:
            email: Customer's email address (from user account)
            amount: Amount in kobo (smallest currency unit).
                    1 Naira = 100 kobo. Convert: naira * 100
            reference: Unique transaction reference for idempotency
        
        Returns:
            dict: Paystack response containing:
                - authorization_url: URL to redirect user for payment
                - access_code: Access code for the transaction
                - reference: Transaction reference (echoed back)
                
        Raises:
            HTTPException:
                - 400 BAD_REQUEST: Invalid parameters sent to Paystack
                - 502 BAD_GATEWAY: Paystack API is down or unreachable
                - 500 INTERNAL_SERVER_ERROR: Other unexpected errors
                
        Example:
            >>> result = await paystack_service.initialize_transaction(
            ...     email="user@example.com",
            ...     amount=50000,  # 500 Naira
            ...     reference="DEP-unique-123"
            ... )
            >>> print(result["authorization_url"])
            'https://checkout.paystack.com/abc123'
        """
        url = f"{self.BASE_URL}/transaction/initialize"
        
        payload = {
            "email": email,
            "amount": amount,
            "reference": reference
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers=self.headers,
                    timeout=30.0
                )
                
                # Parse response
                data = response.json()
                
                # Check if Paystack returned success
                if not data.get("status"):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Paystack error: {data.get('message', 'Unknown error')}"
                    )
                
                return data["data"]
                
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Paystack API timeout - please try again"
            )
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Paystack API error: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to initialize transaction: {str(e)}"
            )
    
    async def verify_transaction(self, reference: str) -> Dict:
        """
        Verify a transaction status with Paystack (FALLBACK METHOD ONLY).
        
        IMPORTANT: This method is for MANUAL verification only.
        DO NOT use this for crediting wallets - webhooks handle that.
        
        This endpoint is provided for:
        - Manual status checks by users
        - Debugging failed webhooks
        - Administrative verification
        
        Args:
            reference: Transaction reference to verify
        
        Returns:
            dict: Paystack response containing transaction details:
                - status: Transaction status
                - amount: Amount in kobo
                - reference: Transaction reference
                - And other transaction metadata
        
        Raises:
            HTTPException:
                - 404 NOT_FOUND: Transaction not found in Paystack
                - 502 BAD_GATEWAY: Paystack API unreachable
                - 500 INTERNAL_SERVER_ERROR: Other errors
                
        Example:
            >>> result = await paystack_service.verify_transaction("DEP-123")
            >>> if result["status"] == "success":
            ...     print("Payment was successful")
        """
        url = f"{self.BASE_URL}/transaction/verify/{reference}"
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers=self.headers,
                    timeout=30.0
                )
                
                data = response.json()
                
                if not data.get("status"):
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Transaction not found: {data.get('message', 'Unknown error')}"
                    )
                
                return data["data"]
                
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Paystack API timeout - please try again"
            )
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Paystack API error: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to verify transaction: {str(e)}"
            )


# Singleton instance - import and use this throughout the application
paystack_service = PaystackService()