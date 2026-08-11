from pydantic import BaseModel, EmailStr, Field


class UserRegisterRequest(BaseModel):
    """Schema for registering a new user account."""
    email:EmailStr
    kdf_salt: str = Field(..., description="Base64 encoded Argon2id salt (min 16 bytes)")
    kdf_memory: int = Field(..., ge=65536, description="Memory cost in KiB (minimum 64 MiB)")
    kdf_iterations: int = Field(..., ge=3, description="Time cost / iterations (minimum 3)")
    kdf_parallelism: int = Field(..., ge=1, description="Parallelism threads (minimum 1)")
    server_password_hash: str = Field(..., max_length=255, description="Argon2id(MPH)")

class UserRegisterResponse(BaseModel):
    """Schema returned after successful registration."""
    message: str
    user_id: str

class PreflightRequest(BaseModel):
    """Phase 1 of Login: Request Argon2id parameters & challenge."""
    email: EmailStr

class PreflightResponse(BaseModel):
    """Response containing KDF params and a 32-byte ephemeral challenge nonce."""
    kdf_salt: str
    kdf_memory: int
    kdf_iterations: int
    kdf_parallelism: int
    auth_challenge: str  

class VerifyChallengeRequest(BaseModel):
    """Phase 2 of Login: Submit HMAC-SHA256 signature for verification."""
    email: EmailStr
    auth_response: str  # Base64 encoded HMAC-SHA256 signature computed using MPH

class TokenResponse(BaseModel):
    """JWT bearer token issued upon successful challenge verification."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int