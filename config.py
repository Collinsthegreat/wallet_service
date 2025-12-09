"""
Configuration module for Wallet Service.

This module uses Pydantic Settings to load and validate environment variables
from a .env file, providing type-safe access to configuration throughout the application.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All settings are loaded from a .env file in the project root.
    Pydantic validates types and provides defaults where specified.
    """
    
    # Database Configuration
    DATABASE_URL: str  # PostgreSQL/MySQL connection string
    
    # JWT Configuration
    JWT_SECRET_KEY: str  # Secret key for signing JWT tokens
    JWT_ALGORITHM: str = "HS256"  # Algorithm for JWT encoding
    JWT_EXPIRATION_MINUTES: int = 10080  # Token expiration time (7 days default)
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID: str  # Google OAuth client ID
    GOOGLE_CLIENT_SECRET: str  # Google OAuth client secret
    GOOGLE_REDIRECT_URI: str  # OAuth callback URL
    
    # Paystack Configuration
    PAYSTACK_SECRET_KEY: str  # Paystack secret key for API calls
    PAYSTACK_PUBLIC_KEY: str  # Paystack public key (for frontend if needed)
    PAYSTACK_WEBHOOK_SECRET: str  # Secret for verifying webhook signatures
    
    # API Key Configuration
    API_KEY_PREFIX: str = "sk_live_"  # Prefix for generated API keys
    MAX_ACTIVE_API_KEYS: int = 5  # Maximum number of active keys per user
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True
    )


# Singleton instance - import this throughout the application
settings = Settings()