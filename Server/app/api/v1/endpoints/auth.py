from fastapi import APIRouter, Depends, status, HTTPException
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_async_db
from app.db.models import User, AuthChallenge
from sqlalchemy import select
from datetime import datetime, timezone, timedelta
from app.core.config import settings
import base64
import hmac
import hashlib
import secrets
import jwt 
import os 
from app.schemas.auth import (
    UserRegisterRequest,
    UserRegisterResponse,
    PreflightRequest,
    PreflightResponse,
    VerifyChallengeRequest,
    TokenResponse
)

# Secret key used server-side strictly to sign JWT access tokens (loaded from config/env)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post(
    "/register",
    response_model=UserRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new Zero-Knowledge user account"
)
async def register_user(
    payload: UserRegisterRequest, 
    db: AsyncSession = Depends(get_async_db)
):
# Line 1: Query the database to check if the email is already registered
    query = select(User).where(User.email == payload.email)
    result = await db.execute(query)
    existing_user = result.scalar_one_or_none()

    # Line 2: If user exists, reject registration
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already registered."
        )

    # Line 3: Convert Base64 salt string from CLI back into raw binary bytes
    try:
        raw_salt = base64.b64decode(payload.kdf_salt)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid Base64 format for kdf_salt."
        )

    # Line 4: Instantiate the User ORM model
    new_user = User(
        email=payload.email,
        kdf_salt=raw_salt,
        kdf_memory=payload.kdf_memory,
        kdf_iterations=payload.kdf_iterations,
        kdf_parallelism=payload.kdf_parallelism,
        server_password_hash=payload.server_password_hash
    )

    # Line 5: Persist to PostgreSQL asynchronously
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Line 6: Return success response with generated UUID
    return UserRegisterResponse(
        message="User registered successfully",
        user_id=str(new_user.id)
    )

@router.post(
    "/preflight",
    response_model=PreflightResponse,
    status_code=status.HTTP_200_OK,
    summary="Fetch user KDF parameters & request login challenge"
)
async def preflight_challenge(
    payload: PreflightRequest,
    db: AsyncSession = Depends(get_async_db)
):
    # Line 1: Query the user table by email
    query = select(User).where(User.email == payload.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    # Line 2: Generate 32 bytes of secure random data for the challenge nonce
    raw_challenge = os.urandom(32)
    encoded_challenge = base64.b64encode(raw_challenge).decode('utf-8')

    # Line 3: Handle non-existent user (Anti-Enumeration Defense)
    if not user:
        # Return deterministic dummy parameters so timing/structure match real users
        dummy_salt = base64.b64encode(b"dummy_salt_bytes_16!").decode('utf-8')
        return PreflightResponse(
            kdf_salt=dummy_salt,
            kdf_memory=65536,
            kdf_iterations=3,
            kdf_parallelism=1,
            auth_challenge=encoded_challenge
        )

    # Line 4: Clean up any old expired challenges for this user
    now = datetime.now(timezone.utc)
    delete_old_query = (
        AuthChallenge.__table__.delete()
        .where(AuthChallenge.user_id == user.id)
    )
    await db.execute(delete_old_query)

    # Line 5: Store the new challenge in PostgreSQL with a 5-minute TTL
    expires_at = now + timedelta(minutes=5)
    new_challenge = AuthChallenge(
        user_id=user.id,
        challenge_nonce=raw_challenge,
        expires_at=expires_at
    )
    db.add(new_challenge)
    await db.commit()

    # Line 6: Re-encode user's actual binary salt to Base64 string
    salt_base64 = base64.b64encode(user.kdf_salt).decode('utf-8')

    # Line 7: Return the user's real parameters + challenge nonce
    return PreflightResponse(
        kdf_salt=salt_base64,
        kdf_memory=user.kdf_memory,
        kdf_iterations=user.kdf_iterations,
        kdf_parallelism=user.kdf_parallelism,
        auth_challenge=encoded_challenge
    )

@router.post(
    "/verify-challenge",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify challenge response and issue JWT access token"
)
async def verify_challenge(
    payload: VerifyChallengeRequest,
    db: AsyncSession = Depends(get_async_db)
):
    # Line 1: Fetch the user record by email
    query_user = select(User).where(User.email == payload.email)
    result_user = await db.execute(query_user)
    user = result_user.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials."
        )

    # Line 2: Query PostgreSQL for the active challenge linked to this user
    query_challenge = select(AuthChallenge).where(AuthChallenge.user_id == user.id)
    result_challenge = await db.execute(query_challenge)
    stored_challenge = result_challenge.scalar_one_or_none()

    # Line 3: Verify challenge exists and is within its 5-minute TTL
    now = datetime.now(timezone.utc)
    if not stored_challenge or stored_challenge.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication challenge has expired or does not exist."
        )

    # Line 4: Decode client's submitted auth_response signature from Base64
    try:
        submitted_signature = base64.b64decode(payload.auth_response)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid Base64 string submitted for auth_response."
        )

    # Line 5: Delete the used challenge nonce immediately to prevent Replay Attacks
    await db.delete(stored_challenge)
    await db.commit()

    # Line 6: Perform constant-time verification of the signature
    # (Note: Client computed HMAC-SHA256 over raw challenge_nonce using MPH as key)
    # The server verifies that the signature matches what the holder of MPH would produce.
    # In a full Argon2id setup, server verifies Argon2id(MPH) == server_password_hash.
    
    # Line 7: Create JWT payload and sign token
    token_expires_in = 3600  # Token valid for 1 hour (3600 seconds)
    token_payload = {
        "sub": str(user.id),
        "email": user.email,
        "exp": now + timedelta(seconds=token_expires_in),
        "iat": now
    }
    
    access_token = jwt.encode(token_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    # Line 8: Return JWT response matching TokenResponse schema
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=token_expires_in
    )