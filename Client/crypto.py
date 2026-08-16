import os, base64
from typing import Tuple
from argon2.low_level import hash_secret_raw, Type 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST = 65536  # 64 MiB in KiB
DEFAULT_PARALLELISM = 4

def derive_master_keys(
    master_password: str,
    salt: bytes,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> Tuple[bytes, bytes]:
    """
    Derives the Master Encryption Key (MEK) and Master Authentication Key (MAK)
    from the master password using Argon2id.

    Returns
        (mek, auth_key): A tuple of two 32-byte keys.
    """
    # Derive 64 raw bytes using Argon2id
    raw_material = hash_secret_raw(
        secret=master_password.encode('utf-8'),
        salt=salt,
        memory_cost=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism,
        hash_len=64,
        type=Type.ID,
    )
    # Split into two 256-bit (32-byte) keys
    mek = raw_material[:32]
    auth_key = raw_material[32:]

    return mek, auth_key

def encrypt_vault_item(
    mek: bytes,
    item_id: str,
    plaintext: str,
) -> dict:
    """
    Encrypts plaintext vault data using AES-256-GCM with Associated Data (AD).

    Args:
        mek: 32-byte Master Encryption Key.
        item_id: UUID string used as Associated Data to prevent swap attacks.
        plaintext: The sensitive string to encrypt.

    Returns:
        dict: Base64-encoded strings {"nonce": ..., "ciphertext": ..., "auth_tag": ...}
    """
    # 1. Generate a cryptographically secure 12-byte nonce (96 bits)
    nonce = os.urandom(12)

    # 2. Associated Data binds the ciphertext to this specific item_id
    associated_data = item_id.encode("utf-8")

    # 3. Encrypt using AES-256-GCM
    aesgcm = AESGCM(mek)
    encrypted_blob = aesgcm.encrypt(
        nonce=nonce,
        data=plaintext.encode("utf-8"),
        associated_data=associated_data,
    )

    # 4. Extract ciphertext and the 16-byte authentication tag
    ciphertext = encrypted_blob[:-16]
    auth_tag = encrypted_blob[-16:]

    # 5. Return Base64-encoded representations for JSON transport
    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "auth_tag": base64.b64encode(auth_tag).decode("utf-8"),
    }


def decrypt_vault_item(
    mek: bytes,
    item_id: str,
    nonce_b64: str,
    ciphertext_b64: str,
    auth_tag_b64: str,
) -> str:
    """
    Decrypts AES-256-GCM encrypted vault data after verifying authentication tag and AD.

    Args:
        mek: 32-byte Master Encryption Key.
        item_id: UUID string used as Associated Data.
        nonce_b64: Base64-encoded 12-byte nonce.
        ciphertext_b64: Base64-encoded ciphertext.
        auth_tag_b64: Base64-encoded 16-byte authentication tag.

    Returns:
        str: Decrypted plaintext string.
    """
    # 1. Decode Base64 strings to raw bytes
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    auth_tag = base64.b64decode(auth_tag_b64)

    # 2. Recombine ciphertext and 16-byte tag for AESGCM.decrypt
    full_encrypted_payload = ciphertext + auth_tag
    associated_data = item_id.encode("utf-8")

    # 3. Decrypt and verify tag
    aesgcm = AESGCM(mek)
    decrypted_bytes = aesgcm.decrypt(
        nonce=nonce,
        data=full_encrypted_payload,
        associated_data=associated_data,
    )

    return decrypted_bytes.decode("utf-8")

