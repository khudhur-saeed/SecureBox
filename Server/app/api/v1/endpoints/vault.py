from uuid import UUID
from typing import List
from fastapi import APIRouter, status, HTTPException,Depends
from sqlalchemy import select 
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_async_db
from app.db.models  import VaultItem, User
from app.api.deps import get_current_user 
from app.schemas.vault import VaultItemResponse, VaultItemCreateRequest, VaultListResponse, VaultItemUpdate
import base64 
import binascii

router = APIRouter(prefix="/vault",tags=["Vault Items"])

@router.get("", response_model=VaultListResponse)
async def get_vault_items(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    # 1. Fetch records for the authenticated user only
    query = select(VaultItem).where(VaultItem.user_id == current_user.id)
    result = await db.execute(query)
    items = result.scalars().all()

    # 2. Convert binary bytes to Base64 strings for each item
    response_items = [
        VaultItemResponse(
            id=item.id,
            user_id=item.user_id,
            nonce=base64.b64encode(item.nonce).decode('utf-8'),
            ciphertext=base64.b64encode(item.ciphertext).decode('utf-8'),
            auth_tag=base64.b64encode(item.auth_tag).decode('utf-8'),
            created_at=item.created_at,
            updated_at=item.updated_at,
        )
        for item in items
    ]

    # 3. Return formatted response
    return VaultListResponse(
        items=response_items,
        total=len(response_items)
    )

@router.post("", response_model=VaultItemResponse, status_code=status.HTTP_201_CREATED)
async def create_vault_item(
    payload: VaultItemCreateRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    # 1. Base64 decode strings to raw bytes
    try:
        raw_nonce = base64.b64decode(payload.nonce)
        raw_ciphertext = base64.b64decode(payload.ciphertext)
        raw_auth_tag = base64.b64decode(payload.auth_tag)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid Base64 encoding in cryptographic fields.",
        )

    # 2. Strict AES-256-GCM length validations
    if len(raw_nonce) != 12:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Nonce must be exactly 12 bytes.",
        )

    if len(raw_auth_tag) != 16:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Authentication tag must be exactly 16 bytes.",
        )

    # 3. Instantiate and persist new VaultItem
    new_item = VaultItem(
        id=payload.id,
        user_id=current_user.id,
        nonce=raw_nonce,
        ciphertext=raw_ciphertext,
        auth_tag=raw_auth_tag,
    )

    db.add(new_item)
    await db.commit()
    await db.refresh(new_item)

    # 4. Return response schema with bytes encoded back to Base64
    return VaultItemResponse(
        id=new_item.id,
        user_id=new_item.user_id,
        nonce=base64.b64encode(new_item.nonce).decode("utf-8"),
        ciphertext=base64.b64encode(new_item.ciphertext).decode("utf-8"),
        auth_tag=base64.b64encode(new_item.auth_tag).decode("utf-8"),
        created_at=new_item.created_at,
        updated_at=new_item.updated_at,
    )

@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vault_item(
    item_id: UUID,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_async_db),
):
    query = select(VaultItem).where(
        VaultItem.id == item_id,
        VaultItem.user_id == current_user.id
    )
    result = await db.execute(query)
    vault_item = result.scalar_one_or_none()

    if vault_item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="There is no matching vault item!"
        )

    await db.delete(vault_item)
    await db.commit()
    return None
    
@router.put("/{item_id}")
async def update_vault_item(
    item_id: UUID,
    payload: VaultItemUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user)
):
    query = select(VaultItem).where(VaultItem.id == item_id,VaultItem.user_id == current_user.id)
    result = await db.execute(query)
    stored_vault_item = result.scalar_one_or_none()

    if stored_vault_item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="There is no matching vault item!"
        )

    try:
        ciphertext_raw = base64.b64decode(payload.ciphertext)
        nonce_raw = base64.b64decode(payload.nonce)
        auth_tag_raw = base64.b64decode(payload.auth_tag)
    except (binascii.Error, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Base64 encoding in payload"
        )

    if len(nonce_raw) != 12 :
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cryptographic parameters"
        )

    if len(auth_tag_raw) != 16 :
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cryptographic parameters"
        )

    stored_vault_item.nonce = nonce_raw
    stored_vault_item.ciphertext = ciphertext_raw
    stored_vault_item.auth_tag = auth_tag_raw
    

    await db.commit()
    await db.refresh(stored_vault_item)

    return VaultItemResponse(
        id=stored_vault_item.id,
        nonce=base64.b64encode(stored_vault_item.nonce).decode('utf-8'),
        ciphertext=base64.b64encode(stored_vault_item.ciphertext).decode('utf-8'),
        auth_tag=base64.b64encode(stored_vault_item.auth_tag).decode('utf-8')
    )

    


