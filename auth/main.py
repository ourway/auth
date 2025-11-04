"""
FastAPI application setup
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth.database import create_tables
from auth.routes import router

# Create tables on startup
create_tables()

# Create FastAPI app
app = FastAPI(
    title="Auth API",
    description="Authorization service with FastAPI and SQLAlchemy",
    version="0.9.1",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router)
