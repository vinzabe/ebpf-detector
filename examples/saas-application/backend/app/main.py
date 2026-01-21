"""
Abejar SaaS Backend - FastAPI Application
==========================================

This is a complete SaaS backend example demonstrating:
- JWT Authentication
- PostgreSQL database integration
- Redis caching
- RESTful API design

All external HTTP requests from this application are routed through
the Abejar PQC VPN Router with Kyber-1024 encryption.

Copyright 2024 Abejar. All rights reserved.
Contact: grant@abejar.net
"""

import os
from contextlib import asynccontextmanager
from datetime import datetime

import httpx
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer

from app.api import auth, users, health
from app.core.config import settings
from app.core.database import engine, Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    print("=" * 50)
    print("  Abejar SaaS Backend Starting...")
    print("=" * 50)
    print(f"  App Name: {settings.APP_NAME}")
    print(f"  Debug: {settings.DEBUG}")
    print(f"  Log Level: {settings.LOG_LEVEL}")
    print("=" * 50)
    
    # Create database tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Verify VPN connection
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("https://ipinfo.io/json", timeout=10)
            ip_info = response.json()
            print(f"  External IP: {ip_info.get('ip', 'Unknown')}")
            print(f"  Location: {ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown')}")
            print(f"  ISP: {ip_info.get('org', 'Unknown')}")
    except Exception as e:
        print(f"  Warning: Could not verify external IP: {e}")
    
    print("=" * 50)
    
    yield
    
    # Shutdown
    print("Abejar SaaS Backend shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    description="Abejar SaaS Backend with PQC VPN Routing",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "app": settings.APP_NAME,
        "version": "1.0.0",
        "status": "running",
        "pqc": "enabled",
        "docs": "/api/docs"
    }


@app.get("/api/external-ip")
async def get_external_ip():
    """
    Get the external IP address.
    This demonstrates that traffic is routed through the VPN.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("https://ipinfo.io/json", timeout=10)
            return response.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Could not fetch external IP: {str(e)}"
        )
