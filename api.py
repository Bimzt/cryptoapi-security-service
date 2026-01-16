from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
from datetime import datetime, timedelta
import base64
import json
import hashlib
import secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = FastAPI(title="Security Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("data", exist_ok=True)
os.makedirs("data/pubkeys", exist_ok=True)
os.makedirs("data/messages", exist_ok=True)
os.makedirs("data/pdfs", exist_ok=True)
os.makedirs("data/sessions", exist_ok=True)

security = HTTPBearer()
SESSIONS = {}

def generate_session_token() -> str:
    return secrets.token_urlsafe(32)

def create_session(username: str) -> dict:
    token = generate_session_token()
    session_data = {
        "username": username,
        "token": token,
        "created_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(hours=24)).isoformat(),
        "active": True
    }
    SESSIONS[token] = session_data
    
    with open(f"data/sessions/{token}.json", "w") as f:
        json.dump(session_data, f, indent=2)
    
    return session_data

def verify_session_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    
    if token not in SESSIONS:
        session_file = f"data/sessions/{token}.json"
        if os.path.exists(session_file):
            with open(session_file, "r") as f:
                SESSIONS[token] = json.load(f)
        else:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    session = SESSIONS[token]

    expires_at = datetime.fromisoformat(session["expires_at"])
    if datetime.now() > expires_at:
        raise HTTPException(status_code=401, detail="Session expired")

    if not session.get("active"):
        raise HTTPException(status_code=401, detail="Session inactive")
    
    return session

def save_user_data(username: str, data: dict):
    filepath = f"data/{username}.txt"
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

def load_user_data(username: str) -> dict:
    filepath = f"data/{username}.txt"
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return None

def get_all_users() -> list:
    users = []
    for filename in os.listdir("data"):
        if filename.endswith(".txt") and filename not in ["messages.txt"]:
            users.append(filename.replace(".txt", ""))
    return users

def save_message(message_data: dict):
    filepath = "data/messages/messages.txt"
    messages = []
    
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            try:
                messages = json.load(f)
            except:
                messages = []
    
    messages.append(message_data)
    
    with open(filepath, "w") as f:
        json.dump(messages, f, indent=2)

def get_messages_for_user(username: str) -> list:
    filepath = "data/messages/messages.txt"
    if not os.path.exists(filepath):
        return []
    
    with open(filepath, "r") as f:
        try:
            all_messages = json.load(f)
            return [msg for msg in all_messages if msg.get("recipient") == username]
        except:
            return []
        
@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def get_index() -> dict:
    return {
        "message": "Hello world! Please visit http://localhost:8080/docs for API UI."
    }

@app.post("/login")
async def login(username: str = Form(...)):
    user_data = load_user_data(username)
    if not user_data:
        raise HTTPException(
            status_code=404, 
            detail="User tidak ditemukan. Silakan upload public key terlebih dahulu via /store"
        )
    
    session = create_session(username)
    
    return {
        "message": f"Login berhasil untuk user '{username}'",
        "session": {
            "token": session["token"],
            "expires_at": session["expires_at"]
        },
        "instructions": {
            "how_to_use": "Copy token di atas dan gunakan di header",
            "example": f"Authorization: Bearer {session['token'][:20]}"
        }
    }

@app.post("/store")
async def store_pubkey(
    username: str = Form(...),
    file: UploadFile = File(...)):
    try:
        if not username or len(username) < 3:
            raise HTTPException(status_code=400, detail="Username harus minimal 3 karakter")
        
        pubkey_content = await file.read()

        if not pubkey_content.startswith(b"-----BEGIN PUBLIC KEY-----"):
            raise HTTPException(status_code=400, detail="File bukan format PEM Public Key yang valid")

        try:
            public_key = serialization.load_pem_public_key(
                pubkey_content,
                backend=default_backend()
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Public key rusak atau format salah: {str(e)}")

        pubkey_path = f"data/pubkeys/{username}_pub.pem"
        with open(pubkey_path, "wb") as f:
            f.write(pubkey_content)

        if isinstance(public_key, ed25519.Ed25519PublicKey):
            key_algo = "ED25519"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_algo = "EC_SECP256K1"
        elif isinstance(public_key, rsa.RSAPublicKey):
            key_algo = "RSA"
        else:
            key_algo = "UNKNOWN KEY TYPE"

        user_data = {
            "username": username,
            "public_key_path": pubkey_path,
            "registered_at": datetime.now().isoformat(),
            "key_type": key_algo}
        save_user_data(username, user_data)
        
        return {
            "message": f"Public key untuk user '{username}' berhasil disimpan",
            "username": username,
            "key_type": key_algo,
            "stored_at": pubkey_path}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.post("/upload-pdf")
async def upload_pdf(
    file: UploadFile = File(...),
    session: dict = Depends(verify_session_token)):
    fname = file.filename
    ctype = file.content_type
    
    try:
        contents = await file.read()
        filepath = f"data/pdfs/{fname}"

        sha256_hash = hashlib.sha256(contents).hexdigest()
        
        with open(filepath, "wb") as f:
            f.write(contents)
            
        return {
            "message": "File uploaded!",
            "filename": fname,
            "content-type": ctype,
            "size_bytes": len(contents),
            "sha256_checksum": sha256_hash,
            "saved_to": filepath,
            "uploaded_by": session["username"]
        }
        
    except Exception as e:
        return {
            "message": str(e)
        }

@app.post("/verify")
async def verify(
    username: str = Form(...),
    message: str = Form(...),
    signature: str = Form(...),
    session: dict = Depends(verify_session_token)):
    try:
        user_data = load_user_data(username)
        if not user_data:
            raise HTTPException(status_code=404, detail=f"User '{username}' tidak ditemukan")

        pubkey_path = user_data.get("public_key_path")

        with open(pubkey_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        try:
            signature_bytes = base64.b64decode(signature)
        except Exception:
            raise HTTPException(status_code=400, detail="Signature harus Base64 valid")
        
        message_variants = []
        message_variants.append(message.encode())
        try:
            message_variants.append(base64.b64decode(message))
        except:
            pass

        is_valid = False
        algo_used = "Unknown"
        last_error = None

        for msg in message_variants:
            try:
                if isinstance(public_key, ed25519.Ed25519PublicKey):
                    public_key.verify(signature_bytes, msg)
                    algo_used = "ED25519"
                    is_valid = True
                    break

                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(signature_bytes, msg, ec.ECDSA(hashes.SHA256()))
                    algo_used = "ECDSA (SECP256K1)"
                    is_valid = True
                    break

                elif isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        signature_bytes,
                        msg,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    algo_used = "RSA-PSS"
                    is_valid = True
                    break

            except Exception as e:
                last_error = str(e)
                continue

        return {
            "valid": is_valid,
            "username": username,
            "algorithm": algo_used,
            "message": "Signature Valid" if is_valid else f"Signature Invalid: {last_error or 'Mismatch'}",
            "verified_by": session["username"]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"System Error: {str(e)}")

@app.post("/relay")
async def relay(
    sender: str = Form(...),
    recipient: str = Form(...),
    encrypted_message: str = Form(...),
    signature: str = Form(...),
    session: dict = Depends(verify_session_token)):
    try:
        sender_data = load_user_data(sender)
        if not sender_data:
            raise HTTPException(status_code=404, detail=f"Sender '{sender}' tidak ditemukan")

        recipient_data = load_user_data(recipient)
        if not recipient_data:
            raise HTTPException(status_code=404, detail=f"Recipient '{recipient}' tidak ditemukan")

        with open(sender_data["public_key_path"], "rb") as f:
            sender_pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        sig_bytes = base64.b64decode(signature)
        msg_bytes = encrypted_message.encode()

        try:
            if isinstance(sender_pub_key, ed25519.Ed25519PublicKey):
                sender_pub_key.verify(sig_bytes, msg_bytes)

            elif isinstance(sender_pub_key, ec.EllipticCurvePublicKey):
                sender_pub_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))

            elif isinstance(sender_pub_key, rsa.RSAPublicKey):
                sender_pub_key.verify(
                    sig_bytes,
                    msg_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

            else:
                raise Exception("Key type unsupported")

        except InvalidSignature:
            raise HTTPException(status_code=401, detail="INTEGRITY CHECK FAILED: Signature tidak valid!")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Verifikasi Error: {str(e)}")

        message_data = {
            "id": f"msg_{datetime.now().timestamp()}",
            "sender": sender,
            "recipient": recipient,
            "encrypted_message": encrypted_message,
            "signature": signature,
            "timestamp": datetime.now().isoformat(),
            "status": "verified_and_relayed",
            "relayed_by": session["username"]
        }

        save_message(message_data)

        return {
            "status": "success",
            "message": "Integrity Check Lulus, Signature valid!",
            "data": message_data
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.post("/sign-pdf")
async def sign_pdf_endpoint(
    username: str = Form(...),
    signature: str = Form(...),
    pdf_checksum: str = Form(...),
    algorithm: str = Form(...),
    session: dict = Depends(verify_session_token)):
    try:
        user_data = load_user_data(username)
        if not user_data:
            raise HTTPException(status_code=404, detail=f"User '{username}' tidak ditemukan")
        
        with open(user_data["public_key_path"], "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        
        sig_bytes = base64.b64decode(signature)
        checksum_bytes = base64.b64decode(pdf_checksum)
        
        is_valid = False
        try:
            if algorithm.upper() == "RSA" and isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    sig_bytes,
                    checksum_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                is_valid = True
            
            elif algorithm.upper() == "EC" and isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(sig_bytes, checksum_bytes, ec.ECDSA(hashes.SHA256()))
                is_valid = True
            
            elif algorithm.upper() == "ED25519" and isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(sig_bytes, checksum_bytes)
                is_valid = True
            
        except InvalidSignature:
            raise HTTPException(status_code=401, detail="PDF Signature tidak valid!")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Verifikasi Error: {str(e)}")
        
        if not is_valid:
            raise HTTPException(status_code=401, detail="Signature verification failed")

        signature_data = {
            "id": f"pdf_sig_{datetime.now().timestamp()}",
            "username": username,
            "signature": signature,
            "pdf_checksum": pdf_checksum,
            "algorithm": algorithm.upper(),
            "timestamp": datetime.now().isoformat(),
            "status": "verified",
            "signed_by_session": session["username"]
        }

        sig_file = f"data/pdfs/signatures_{username}.json"
        signatures = []
        if os.path.exists(sig_file):
            with open(sig_file, "r") as f:
                try:
                    signatures = json.load(f)
                except:
                    signatures = []
        
        signatures.append(signature_data)
        
        with open(sig_file, "w") as f:
            json.dump(signatures, f, indent=2)
        
        return {
            "status": "success",
            "message": f"PDF berhasil ditandatangani oleh {username}",
            "data": signature_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.post("/verify-pdf-signature")
async def verify_pdf_signature(
    username: str = Form(...),
    signature: str = Form(...),
    pdf_checksum: str = Form(...),
    session: dict = Depends(verify_session_token)):
    try:
        user_data = load_user_data(username)
        if not user_data:
            raise HTTPException(status_code=404, detail=f"User '{username}' tidak ditemukan")
        
        with open(user_data["public_key_path"], "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        
        sig_bytes = base64.b64decode(signature)
        checksum_bytes = base64.b64decode(pdf_checksum)
        
        is_valid = False
        algo_used = "Unknown"
        
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    sig_bytes,
                    checksum_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                algo_used = "RSA-PSS"
                is_valid = True
            
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(sig_bytes, checksum_bytes, ec.ECDSA(hashes.SHA256()))
                algo_used = "ECDSA"
                is_valid = True
            
            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(sig_bytes, checksum_bytes)
                algo_used = "ED25519"
                is_valid = True
        
        except InvalidSignature:
            is_valid = False
        
        return {
            "valid": is_valid,
            "username": username,
            "algorithm": algo_used,
            "message": "PDF Signature Valid" if is_valid else "PDF Signature Invalid",
            "verified_by": session["username"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.post("/logout")
async def logout(session: dict = Depends(verify_session_token)):
    token = None
    for t, s in SESSIONS.items():
        if s["username"] == session["username"]:
            token = t
            break
    
    if token:
        SESSIONS[token]["active"] = False
        with open(f"data/sessions/{token}.json", "w") as f:
            json.dump(SESSIONS[token], f, indent=2)
    
    return {"message": f"Logout berhasil untuk user '{session['username']}'"}

@app.get("/protected")
async def protected_endpoint(session: dict = Depends(verify_session_token)):
    return {
        "message": "Akses ke protected resource berhasil",
        "user": session["username"],
        "session_created": session["created_at"]
    }

@app.get("/users")
async def get_users(session: dict = Depends(verify_session_token)):
    users = get_all_users()
    user_details = []
    
    for username in users:
        user_data = load_user_data(username)
        if user_data:
            user_details.append({
                "username": user_data.get("username"),
                "key_type": user_data.get("key_type")
            })
    
    return {
        "users": user_details,
        "total": len(user_details),
        "requested_by": session["username"]
    }

@app.get("/messages/{username}")
async def get_user_messages(
    username: str,
    session: dict = Depends(verify_session_token)):
    user_data = load_user_data(username)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    if username != session["username"]:
        raise HTTPException(
            status_code=403,
            detail=f"Anda hanya bisa akses message untuk username sendiri ({session['username']})"
        )
    
    messages = get_messages_for_user(username)
    return {
        "inbox": messages,
        "total": len(messages),
        "username": username
    }

@app.delete("/user/{username}")
async def delete_user(
    username: str,
    session: dict = Depends(verify_session_token)):
    if username != session["username"]:
        raise HTTPException(
            status_code=403,
            detail="Anda hanya bisa delete username sendiri"
        )
    
    user_data = load_user_data(username)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
        
    if os.path.exists(f"data/{username}.txt"):
        os.remove(f"data/{username}.txt")
        
    pubkey_path = user_data.get("public_key_path")
    if pubkey_path and os.path.exists(pubkey_path):
        os.remove(pubkey_path)
    
    return {"message": f"User '{username}' dan key-nya berhasil dihapus"}

@app.get("/stats")
async def get_statistics(session: dict = Depends(verify_session_token)):
    total_users = len(get_all_users())
    messages = []
    if os.path.exists("data/messages/messages.txt"):
        with open("data/messages/messages.txt", "r") as f:
            try:
                messages = json.load(f)
            except:
                pass
    
    pdf_count = len([f for f in os.listdir("data/pdfs") if f.endswith(".pdf")])
    active_sessions = sum(1 for s in SESSIONS.values() if s.get("active"))
    
    return {
        "total_users": total_users,
        "total_messages": len(messages),
        "total_pdfs": pdf_count,
        "active_sessions": active_sessions,
        "timestamp": datetime.now().isoformat(),
        "requested_by": session["username"]
    }