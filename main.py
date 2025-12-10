"""
FastAPI Wallet Service Application.

Main entry point for the wallet service API.
Includes all routers and middleware configuration.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import engine, Base
from routers import auth_router, keys_router, wallet_router

from starlette.middleware.sessions import SessionMiddleware
from config import settings  # Make sure settings.JWT_SECRET_KEY exists

# Create database tables
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="Wallet Service API",
    description="A complete wallet service with Paystack integration, JWT authentication, and API keys",
    version="1.0.0",
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True
    }
)

# Add security schemes for Swagger UI
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Wallet Service API",
        version="1.0.0",
        description="A complete wallet service with Paystack integration, JWT authentication, and API keys",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "bearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter JWT token"
        },
        "api-key": {
            "type": "apiKey",
            "in": "header",
            "name": "x-api-key",
            "description": "Enter API key"
        }
    }
    openapi_schema["security"] = [
    {"bearer": []},
    {"api-key": []}
]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Add CORS middleware (configure for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SessionMiddleware, secret_key=settings.JWT_SECRET_KEY)

# Include routers
app.include_router(auth_router.router)
app.include_router(keys_router.router)
app.include_router(wallet_router.router)


@app.get("/")
def health_check():
    """
    Health check endpoint.
    
    Returns basic API information and status.
    
    Returns:
        dict: Status and message
        
    Example Response:
        {
            "status": "ok",
            "message": "Wallet Service API is running",
            "version": "1.0.0"
        }
    """
    return {
        "status": "ok",
        "message": "Wallet Service API is running",
        "version": "1.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
