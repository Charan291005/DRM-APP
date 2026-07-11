"""
routers/auth_router.py — Creator account registration and login.

Endpoints:
  POST /auth/register  — Create a new creator account
  POST /auth/login     — Login, receive JWT access token
  GET  /auth/me        — Get current user's profile
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db
from models import User
from schemas import RegisterRequest, LoginRequest, TokenResponse, UserProfile
from auth import hash_password, verify_password, create_access_token, get_current_user
from config import get_settings

settings = get_settings()
router  = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserProfile,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new creator account",
)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Check if email already exists
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        email           = body.email,
        hashed_password = hash_password(body.password),
        full_name       = body.full_name,
    )
    db.add(user)
    await db.flush()   # Assigns the UUID before commit
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and receive a JWT bearer token",
)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user   = result.scalar_one_or_none()

    if user is None or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated.",
        )

    expire_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(subject=user.id, expires_delta=expire_delta)

    return TokenResponse(
        access_token=token,
        expires_in=int(expire_delta.total_seconds()),
    )


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get the currently authenticated creator's profile",
)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user
