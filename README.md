# Cryptographic Security & Data Integrity Service

> A RESTful API service built with **FastAPI** that implements asymmetric cryptography for data security, message integrity verification, and digital signing of documents — supporting **RSA**, **ECDSA (secp256k1)**, and **Ed25519** algorithms.

---

## Overview

CryptoAPI is a backend security service that demonstrates a practical implementation of Public Key Infrastructure (PKI) concepts. The system enables:

- **Key-based user identity** — users are registered via their public key, not a password
- **End-to-end message relay** with mandatory signature verification before delivery
- **PDF document signing and verification** using cryptographic checksums
- **Session-based authentication** with time-limited bearer tokens
- **Multi-algorithm support** — the server auto-detects RSA, EC, or Ed25519 key types

This project was built to explore how cryptographic primitives are applied in real-world API services, translating theoretical security concepts (digital signatures, hash integrity, asymmetric key pairs) into working endpoints.

---

## Architecture

```
┌─────────────────────────────────────────┐
│           Client (client.py)            │
│  - Generates RSA / EC / Ed25519 keypair │
│  - Signs messages and PDF hashes locally│
│  - Uploads public key to server         │
└────────────────┬────────────────────────┘
                 │  HTTPS / Bearer Token
┌────────────────▼────────────────────────┐
│         FastAPI Server (api.py)         │
│                                         │
│  ┌─────────────────────────────────┐    │
│  │  Auth Layer (Bearer Token)      │    │
│  │  - Login → Session Token (24h)  │    │
│  │  - Token validation per request │    │
│  └────────────────┬────────────────┘    │
│                   │                     │
│  ┌────────────────▼────────────────┐    │
│  │  Crypto Verification Engine     │    │
│  │  - RSA-PSS + SHA256             │    │
│  │  - ECDSA + SHA256               │    │
│  │  - Ed25519 (pure)               │    │
│  └────────────────┬────────────────┘    │
│                   │                     │
│  ┌────────────────▼────────────────┐    │
│  │  File-based Storage             │    │
│  │  data/pubkeys/ | sessions/      │    │
│  │  data/messages/ | pdfs/         │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

---

## Project Structure

```
📦 cryptoapi/
├── 📄 main.py              # Server entry point (uvicorn launcher)
├── 📄 api.py               # Core FastAPI application & all endpoints
├── 📄 client.py            # Client-side key generator & signing utility
├── 📄 pyproject.toml       # Project metadata & pinned dependencies (uv)
├── 📄 uv.lock              # Lockfile for reproducible installs
├── 📁 punkhazard-keys/     # Sample pre-generated key pairs (for testing)
└── 📁 data/                # Auto-created at runtime
    ├── pubkeys/            # Registered user public keys (.pem)
    ├── messages/           # Relayed messages (JSON)
    ├── pdfs/               # Uploaded PDFs & signature records
    └── sessions/           # Active session tokens (JSON)
```

---

## Key Features & API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/store` | Register user by uploading a PEM public key |
| `POST` | `/login` | Authenticate and receive a 24-hour Bearer token |
| `POST` | `/logout` | Invalidate the current session |
| `GET`  | `/protected` | Verify session is active |

### Cryptographic Operations
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/verify` | Verify a digital signature against a registered public key |
| `POST` | `/relay` | Send an encrypted + signed message; server verifies integrity before relaying |
| `POST` | `/sign-pdf` | Submit a PDF checksum + signature for server-side verification & storage |
| `POST` | `/verify-pdf-signature` | Verify a previously stored PDF digital signature |
| `POST` | `/upload-pdf` | Upload a PDF and receive its SHA-256 checksum |

### User & System Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/users` | List all registered users and their key types |
| `GET`  | `/messages/{username}` | Retrieve inbox (owner-only access) |
| `DELETE` | `/user/{username}` | Delete user account and public key |
| `GET`  | `/stats` | Server statistics (users, messages, PDFs, active sessions) |
| `GET`  | `/health` | Health check |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Web Framework | FastAPI 0.104.1 |
| Cryptography | `cryptography` library ≥ 46.0 (RSA-PSS, ECDSA, Ed25519) |
| Server | Uvicorn 0.24.0 (ASGI) |
| Data Validation | Pydantic v2 |
| Package Manager | `uv` (fast Python package manager) |
| Key Format | PEM (PKCS#8 / SubjectPublicKeyInfo) |
| Signature Encoding | Base64 |
| Hashing | SHA-256 |

---

## Getting Started

### Prerequisites

- Python **3.10** (pinned — see `pyproject.toml`)
- [`uv`](https://docs.astral.sh/uv/) package manager

```bash
# Install uv (if not already installed)
pip install uv
```

### 1. Clone the Repository

```bash
git clone https://github.com/Bimzt/Data-security-and-integrity-cryptographic-API-services
cd Data-security-and-integrity-cryptographic-API-services
```

### 2. Install Dependencies

```bash
uv sync
```

> **Alternative (pip):** See `requirements.txt` for standard pip installation.

### 3. Start the Server

```bash
uv run main.py
```

Server starts at: `http://0.0.0.0:8080`  
Interactive API docs: `http://localhost:8080/docs`

---

## Client Usage

The `client.py` script handles the **client-side cryptographic operations** — key generation and signing — which should never be done on the server.

### Generate Key Pairs

```bash
uv run client.py
```

This will:
1. Create a `keys/` directory
2. Generate `_priv.pem` and `_pub.pem` files for your chosen algorithm
3. Simulate signing a sample PDF hash to confirm the keys work

### Supported Algorithms

| Algorithm | Use Case | Key Size / Curve |
|-----------|----------|-----------------|
| **RSA** | Legacy compatibility, document signing | 2048-bit |
| **EC (ECDSA)** | Compact signatures, high performance | secp256k1 |
| **Ed25519** | Modern, fast, no parameter choices needed | 255-bit |

---

## Usage Workflow

```
1. CLIENT: Generate keypair locally (client.py)
         ↓
2. CLIENT → SERVER: Upload public key via POST /store
         ↓
3. CLIENT → SERVER: Login via POST /login → receive Bearer token
         ↓
4. CLIENT: Sign message/PDF hash locally using private key
         ↓
5. CLIENT → SERVER: Send signed data (relay/sign-pdf/verify)
         ↓
6. SERVER: Verifies signature using stored public key
         ↓
7. SERVER: Returns verification result or relays message
```

> **Security Note:** Private keys **never leave the client**. The server only stores public keys and verifies signatures — it cannot decrypt messages or forge signatures.

---

## Data Storage

Data is stored as flat files (no database required):

```
data/
├── {username}.txt          # User metadata (JSON)
├── pubkeys/{username}_pub.pem   # Registered public keys
├── messages/messages.txt   # All relayed messages (JSON array)
├── pdfs/                   # Uploaded PDF files
├── pdfs/signatures_{username}.json  # Per-user PDF signature records
└── sessions/{token}.json   # Session persistence across restarts
```

> To fully reset the server state, delete the contents of the `data/` directory.

---

## Security Considerations

This project is intended as an **educational/portfolio demonstration**. For production use, the following improvements should be considered:

- Replace file-based storage with a proper database (PostgreSQL, etc.)
- Add HTTPS/TLS termination
- Implement rate limiting on authentication endpoints
- Store session tokens in Redis with TTL enforcement
- Add input sanitization to prevent path traversal in file operations
- Use a secrets vault for any sensitive configuration