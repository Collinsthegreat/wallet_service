"""
Database configuration and session management.

This module sets up SQLAlchemy engine, session factory, and provides
a dependency function for FastAPI routes to get database sessions.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import settings

# Create SQLAlchemy engine with connection health checks
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True  # Enable connection health checks before using connections
)

# Session factory for creating database sessions
SessionLocal = sessionmaker(
    autocommit=False,  # Disable autocommit for explicit transaction control
    autoflush=False,   # Disable autoflush for better control
    bind=engine
)

# Base class for all ORM models
Base = declarative_base()


def get_db():
    """
    FastAPI dependency that provides a database session.
    
    Yields a database session and ensures it's properly closed
    after the request is completed, even if an exception occurs.
    
    Yields:
        Session: SQLAlchemy database session
        
    Example:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()