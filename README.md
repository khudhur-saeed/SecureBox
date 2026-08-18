
# 🔐 SecureBox

> [!abstract] Project Overview  
> **SecureBox** is an end-to-end **Zero-Knowledge CLI Password Manager** with a REST API backend.
> 
> **Stack:** Python · FastAPI · PostgreSQL · Typer · Rich · SQLAlchemy · Alembic

## 🎯 Core Principle

> [!important] Zero-Knowledge Architecture  
> The backend never has access to the user's **master password**, **plaintext credentials**, or **Master Encryption Key (MEK)**.
> 
> Key derivation and encryption/decryption are performed **client-side** on the user's machine.

---

## 🏗️ Architecture

```
flowchart TB
    subgraph Client["💻 Client Side"]
        MP["Master Password + Salt"]
        KDF["Argon2id KDF"]
        MP --> KDF

        KDF --> MEK["Master Encryption Key<br/>32 bytes · RAM only"]
        KDF --> MAK["Master Authentication Key<br/>32 bytes"]

        DATA["Plaintext Vault Data"]
        AD["Item UUID<br/>Associated Data"]

        DATA --> AES["AES-256-GCM"]
        MEK --> AES
        AD --> AES

        AES --> ENC["Nonce · Ciphertext · Auth Tag"]

        MAK --> CR["Challenge-Response"]
    end

    subgraph Transport["🌐 HTTPS / TLS"]
        CR
        ENC
    end

    subgraph Server["🖥️ Server Side"]
        API["FastAPI"]
        DB[("PostgreSQL")]
        CH["Challenge Nonce<br/>32 bytes · 5 min TTL"]
        JWT["Short-Lived JWT"]

        API --> DB
        API --> CH
        API --> JWT
    end

    CR --> API
    ENC --> API
```

---

## 🔑 Cryptographic Design

### 1. Split-Key Derivation — Argon2id

When a user registers or logs in:

1. The client receives the **Master Password**.
    
2. A cryptographically random **16-byte salt** is used.
    
3. Argon2id derives **64 raw bytes** using:
    
    - `time_cost = 3`
        
    - `memory_cost = 64 MiB`
        
    - `parallelism = 4`
        
4. The 64 bytes are split into two 32-byte keys.
    

|Key|Size|Purpose|Server?|
|---|---|---|---|
|**MEK**|32 bytes|Encrypt/decrypt vault data|❌ Never transmitted|
|**MAK**|32 bytes|Authentication|✅ Sent as `server_password_hash`|

> [!tip] MEK  
> The **Master Encryption Key** remains in client-side RAM for the session and is purged when the client exits.

> [!warning] MAK Terminology  
> The **Master Authentication Key (MAK)** is transmitted to the server as `server_password_hash` for authentication.

---

### 2. AES-256-GCM

Vault credentials are serialized as JSON and encrypted locally.

```
Plaintext JSON
     │
     ▼
AES-256-GCM
     │
     ├── Nonce       → 12 bytes
     ├── Ciphertext
     └── Auth Tag    → 16 bytes
```

Each vault item uses:

- **AES-256-GCM** for authenticated encryption.
    
- A random **12-byte nonce**.
    
- The item's **UUID as Associated Data (AD)**.
    
- A **16-byte authentication tag**.
    

> [!important] Associated Data  
> The item's UUID is cryptographically bound to the ciphertext. This prevents an attacker from swapping ciphertext between vault records.

---

## 🔐 Authentication Flow

```
sequenceDiagram
    participant C as Client
    participant S as FastAPI
    participant DB as PostgreSQL

    C->>S: POST /auth/preflight (email)
    S->>DB: Lookup user
    DB-->>S: Salt + KDF parameters
    S-->>C: Salt + KDF params + challenge

    C->>C: Argon2id(Master Password)
    C->>C: Derive MEK + MAK
    C->>C: Calculate challenge response

    C->>S: POST /auth/verify-challenge
    S->>S: compare_digest()
    S->>S: Invalidate challenge
    S-->>C: Short-lived JWT
```

### Anti-Enumeration

> [!shield] Account Enumeration Protection  
> If an email does not exist, the server returns **deterministic dummy KDF parameters** and an ephemeral challenge instead of revealing whether the account exists.

### Replay Protection

- Challenge size: **32 bytes**
    
- TTL: **5 minutes**
    
- Challenge is deleted immediately after successful verification.
    
- Verification uses `secrets.compare_digest()`.
    
- JWT is issued only after successful challenge verification.
    

---

## 📁 Project Structure

```
SecureBox/
├── docker-compose.yml
├── .env
├── requirements.txt
│
├── Client/
│   ├── __init__.py
│   ├── main.py
│   ├── crypto.py
│   └── api_client.py
│
└── Server/
    ├── alembic.ini
    ├── alembic/
    │   ├── env.py
    │   └── versions/
    │
    └── app/
        ├── main.py
        ├── core/
        │   └── config.py
        ├── db/
        │   ├── base.py
        │   ├── models.py
        │   └── session.py
        ├── schemas/
        │   ├── auth.py
        │   └── vault.py
        └── api/
            ├── deps.py
            └── v1/
                ├── router.py
                └── endpoints/
                    ├── auth.py
                    └── vault.py
```

---

## 🧩 Components

### Client

|   |   |
|---|---|
|File|Responsibility|
|`crypto.py`|Argon2id KDF + AES-256-GCM|
|`api_client.py`|Backend communication via `httpx`|
|`main.py`|Typer/Rich interactive CLI|

### Server

|   |   |
|---|---|
|Component|Responsibility|
|FastAPI|REST API|
|SQLAlchemy + asyncpg|Async PostgreSQL access|
|Alembic|Database migrations|
|Pydantic|Request/response schemas|
|PostgreSQL|Encrypted vault storage|

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+ _(tested with Python 3.14)_
    
- Docker
    
- Docker Compose
    

### 1. Configure Environment

Create `.env` in the project root:

```
DATABASE_URL=postgresql+asyncpg://securebox_user:securebox_password@localhost:5432/securebox_db
JWT_SECRET_KEY=your_secure_random_64_character_hex_key_here
JWT_ALGORITHM=HS256
```

> [!warning] Secrets  
> Never commit `.env` or real secrets to Git.

### 2. Start PostgreSQL

```
docker compose up -d
```

### 3. Create Virtual Environment

```
python -m venv env
source env/bin/activate
```

Windows:

```
env\Scripts\activate
```

Install dependencies:

```
pip install -r requirements.txt
```

### 4. Run Migrations

```
cd Server
alembic upgrade head
cd ..
```

### 5. Start FastAPI

```
uvicorn Server.app.main:app --host 127.0.0.1 --port 8000 --reload
```

API documentation:

- Swagger UI → `http://127.0.0.1:8000/docs`
    
- ReDoc → `http://127.0.0.1:8000/redoc`
    

---

## 💻 CLI

### Register

```
python -m Client.main register
```

> Derives the salt and cryptographic keys locally before creating the account.

### Login

```
python -m Client.main login
```

> Fetches account parameters, derives the MEK into memory, and starts the interactive shell.

### Interactive Commands

|   |   |
|---|---|
|Command|Action|
|`list`|Fetch and decrypt vault items|
|`add`|Encrypt and upload a new vault item|
|`delete <UUID>`|Permanently delete a vault item|
|`help`|Show available commands|
|`exit` / `quit`|Purge keys from RAM and exit|

---

## 📡 REST API

### Authentication — `/api/v1/auth`

|   |   |   |
|---|---|---|
|Method|Endpoint|Purpose|
|`POST`|`/register`|Register user with KDF parameters and MAK|
|`POST`|`/preflight`|Fetch KDF parameters and issue challenge|
|`POST`|`/verify-challenge`|Verify challenge and return JWT|

### Vault — `/api/v1/vault`

> [!note] Authentication  
> Vault endpoints require a **Bearer Token**.

|   |   |   |
|---|---|---|
|Method|Endpoint|Purpose|
|`GET`|`/`|List encrypted vault items|
|`POST`|`/`|Store pre-encrypted vault item|
|`DELETE`|`/{item_id}`|Delete a vault item|

---

## 🛡️ Database Integrity

PostgreSQL enforces cryptographic byte-length constraints at the database layer.

|   |   |
|---|---|
|Field|Constraint|
|`users.kdf_salt`|≥ 16 bytes|
|`vault_items.nonce`|Exactly 12 bytes|
|`vault_items.auth_tag`|Exactly 16 bytes|
|User relationships|Cascading deletes|

---

## 🧠 Security Model

### What the Server Knows

- User email/account metadata
    
- KDF salt
    
- KDF parameters
    
- `server_password_hash` / MAK
    
- Encrypted vault records
    
- Nonces
    
- Authentication tags
    
- Short-lived authentication challenges
    
- JWT session information
    

### What the Server Does **Not** Know

> [!success] Zero-Knowledge Boundary
> 
> - ❌ Master Password
>     
> - ❌ Master Encryption Key (MEK)
>     
> - ❌ Plaintext vault credentials
>     
> - ❌ Plaintext notes/passwords
>     

---

## 🔄 Vault Encryption Lifecycle

```
flowchart LR
    P["Plaintext Credentials"]
    J["JSON Serialization"]
    E["AES-256-GCM"]
    S["Encrypted Blob"]
    DB[("PostgreSQL")]
    R["Retrieve"]
    D["Decrypt"]
    O["Plaintext"]

    P --> J --> E --> S --> DB
    DB --> R --> D --> O
```

---

## 🔒 Security Properties

|   |   |
|---|---|
|Property|Mechanism|
|Password-based key derivation|Argon2id|
|Data confidentiality|AES-256|
|Data integrity|GCM Authentication Tag|
|Record binding|UUID as Associated Data|
|Replay protection|One-time challenge + TTL|
|Timing attack resistance|`secrets.compare_digest()`|
|Transport security|HTTPS/TLS|
|Session authentication|Short-lived JWT|
|Database integrity|PostgreSQL constraints|
|Zero-knowledge design|Client-side cryptographic operations|

---

## 📚 Learning Notes

> [!question] Key Concepts to Review
> 
> - Argon2id and memory-hard KDFs
>     
> - Key derivation and split-key design
>     
> - AES-256-GCM
>     
> - Nonce vs ciphertext vs authentication tag
>     
> - Associated Data (AD)
>     
> - Challenge-response authentication
>     
> - Replay attacks
>     
> - Account enumeration
>     
> - Constant-time comparison
>     
> - JWT authentication
>     
> - Zero-Knowledge architecture
>     

---

## 📝 Project Documentation

> [!info] README  
> The project README was generated as part of the SecureBox documentation.

---

## 🔗 Quick Links

- **API Base:** `/api/v1`
    
- **Auth:** `/api/v1/auth`
    
- **Vault:** `/api/v1/vault`
    
- **Swagger:** `http://127.0.0.1:8000/docs`
    
- **ReDoc:** `http://127.0.0.1:8000/redoc`
    

---

## 📌 Project Status

**Status:** `Active`

> [!summary] SecureBox in One Sentence  
> **SecureBox is a client-side encrypted password manager where Argon2id derives separate authentication and encryption keys, AES-256-GCM protects vault data, and the server stores only the information required to authenticate users and synchronize encrypted records.**
