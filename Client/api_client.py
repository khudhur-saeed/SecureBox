from typing import Any, Dict, List, Optional
import httpx


class ApiClient:

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")
        self.access_token: Optional[str] = None
        self.client = httpx.Client(base_url=self.base_url, timeout=10.0)

    def close(self) -> None:
        """Closes the underlying HTTP client session and releases connection sockets."""
        self.client.close()

    # --------------------------------------------------------------------------
    # Authentication Endpoints
    # --------------------------------------------------------------------------

    def prelogin(self, email: str) -> Dict[str, Any]:
        """Fetches the user's public salt and Argon2 KDF parameters prior to key derivation."""
        response = self.client.post("/api/v1/auth/preflight", json={"email": email})
        response.raise_for_status()
        return response.json()

    def register(
        self,
        email: str,
        kdf_salt_b64: str,
        server_password_hash_b64: str,
        kdf_memory: int = 65536,
        kdf_iterations: int = 3,
        kdf_parallelism: int = 4,
    ) -> Dict[str, Any]:
        """
        Registers a new user account with their public salt, KDF parameters,
        and derived MAK/server authentication key.
        """
        payload = {
            "email": email,
            "kdf_salt": kdf_salt_b64,
            "kdf_memory": kdf_memory,
            "kdf_iterations": kdf_iterations,
            "kdf_parallelism": kdf_parallelism,
            "server_password_hash": server_password_hash_b64,
        }
        response = self.client.post("/api/v1/auth/register", json=payload)
        response.raise_for_status()
        return response.json()

    def login(self, email: str, auth_key_b64: str) -> str:
        """Authenticates using the derived MAK, retrieves JWT access token, and sets session header."""
        payload = {
            "email": email,
            "auth_response": auth_key_b64,
        }
        response = self.client.post("/api/v1/auth/verify-challenge", json=payload)
        response.raise_for_status()

        data = response.json()
        token = data["access_token"]
        self.access_token = token
        self.client.headers.update({"Authorization": f"Bearer {token}"})
        return token

    # --------------------------------------------------------------------------
    # Protected Vault Endpoints
    # --------------------------------------------------------------------------

    def list_vault_items(self) -> List[Dict[str, Any]]:
        """Fetches all encrypted vault items for the authenticated user from the backend."""
        response = self.client.get("/api/v1/vault")
        response.raise_for_status()
        data = response.json()
        return data.get("items", [])

    def create_vault_item(
        self,
        item_id: str,
        nonce_b64: str,
        ciphertext_b64: str,
        auth_tag_b64: str,
    ) -> Dict[str, Any]:
        """Uploads a new pre-encrypted AES-256-GCM vault entry to the backend."""
        payload = {
            "id": item_id,
            "nonce": nonce_b64,
            "ciphertext": ciphertext_b64,
            "auth_tag": auth_tag_b64,
        }
        response = self.client.post("/api/v1/vault", json=payload)
        response.raise_for_status()
        return response.json()

    def delete_vault_item(self, item_id: str) -> bool:
        """Requests permanent deletion of a specific vault item by its UUID."""
        response = self.client.delete(f"/api/v1/vault/{item_id}")
        response.raise_for_status()
        return response.status_code == 204

    def update_vault_item(self, item_id: str, nonce_b64: str, auth_tag_b64: str, ciphertext_b64: str) -> dict:
        """Sends updated encrypted item data to the server."""
        payload ={
            "ciphertext":ciphertext_b64,
            "nonce":nonce_b64,
            "auth_tag":auth_tag_b64
        }
        response=self.client.put(f"/api/v1/vault/{item_id}",json=payload)
        response.raise_for_status()
        return response.json()

    
