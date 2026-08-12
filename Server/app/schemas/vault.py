from uuid import UUID
from typing import List
from pydantic import BaseModel, Field

class VaultItemCreateRequest(BaseModel):
    """Schema for storing an encrypted vault item."""
    id: UUID = Field(..., description="Client-generated UUID used as Associated Data (AD)")
    nonce: str = Field(..., description="Base64 encoded 12-byte initialization vector")
    ciphertext: str = Field(..., description="Base64 encoded AES-256-GCM encrypted payload")
    auth_tag: str = Field(..., description="Base64 encoded 16-byte authentication tag")

class VaultItemResponse(BaseModel):
    """Schema returned when reading encrypted vault items."""
    id: UUID
    nonce: str
    ciphertext: str
    auth_tag: str

    class Config:
        from_attributes = True

class VaultListResponse(BaseModel):
    """Container schema for returning multiple vault items."""
    items: List[VaultItemResponse] 
