from cryptography.hazmat.primitives.asymmetric import ec, padding, ed25519, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import json

def generate_rsa_keys(username: str, key_size: int = 2048):
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    pub_key = priv_key.public_key()
    os.makedirs("keys", exist_ok=True)
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"keys/{username}_priv.pem", "wb") as f:
        f.write(priv_pem)
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"keys/{username}_pub.pem", "wb") as f:
        f.write(pub_pem)
    
    print(f"\nRSA Keys {username} berhasil dibuat!")
    print(f"Private: keys/{username}_priv.pem")
    print(f"Public:  keys/{username}_pub.pem")
    return priv_key, pub_key

def generate_ec_keys(username: str):
    priv_key = ec.generate_private_key(
        ec.SECP256K1(),
        default_backend()
    )
    pub_key = priv_key.public_key()
    os.makedirs("keys", exist_ok=True)
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"keys/{username}_ec_priv.pem", "wb") as f:
        f.write(priv_pem)
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"keys/{username}_ec_pub.pem", "wb") as f:
        f.write(pub_pem)
    
    print(f"\nEC Keys {username} berhasil dibuat!")
    print(f"Private: keys/{username}_ec_priv.pem")
    print(f"Public:  keys/{username}_ec_pub.pem")
    
    return priv_key, pub_key

def generate_ed25519_keys(username: str):
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    os.makedirs("keys", exist_ok=True)
    
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"keys/{username}_ed25519_priv.pem", "wb") as f:
        f.write(priv_pem)
    
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"keys/{username}_ed25519_pub.pem", "wb") as f:
        f.write(pub_pem)
    
    print(f"\nED25519 Keys {username} berhasil dibuat!")
    print(f"Private: keys/{username}_ed25519_priv.pem")
    print(f"Public:  keys/{username}_ed25519_pub.pem")
    return priv_key, pub_key

def load_rsa_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_rsa_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def encrypt_message(message: str, recipient_pub_key_path: str) -> dict:
    with open(recipient_pub_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    if isinstance(pub_key, rsa.RSAPublicKey):
        encrypted_aes_key = pub_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        encrypted_aes_key = aes_key
    
    combined = {
        "encrypted_message": base64.b64encode(encrypted_message).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "algorithm": "RSA-OAEP+AES256" if isinstance(pub_key, rsa.RSAPublicKey) else "AES256"
    }
    
    return combined

def decrypt_message(encrypted_data: dict, recipient_priv_key_path: str) -> str:
    with open(recipient_priv_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    
    encrypted_message = base64.b64decode(encrypted_data["encrypted_message"])
    encrypted_aes_key = base64.b64decode(encrypted_data["encrypted_aes_key"])
    iv = base64.b64decode(encrypted_data["iv"])
    if isinstance(priv_key, rsa.RSAPrivateKey):
        aes_key = priv_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        aes_key = encrypted_aes_key
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_message) + decryptor.finalize()
    
    return decrypted.decode()

def sign_message_ec(message: str, sender_priv_key_path: str) -> str:
    with open(sender_priv_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    signature = priv_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    signature_b64 = base64.b64encode(signature).decode()
    return signature_b64

def verify_signature_ec(message: str, signature_b64: str, sender_pub_key_path: str) -> bool:
    with open(sender_pub_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read(), default_backend())
    
    try:
        signature = base64.b64decode(signature_b64)
        pub_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
    
def sign_message_ed25519(message: str, sender_priv_key_path: str) -> str:
    with open(sender_priv_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    signature = priv_key.sign(message.encode())
    return base64.b64encode(signature).decode()

def verify_signature_ed25519(message: str, signature_b64: str, sender_pub_key_path: str) -> bool:
    with open(sender_pub_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read(), default_backend())
    
    try:
        signature = base64.b64decode(signature_b64)
        pub_key.verify(signature, message.encode())
        return True
    except Exception:
        return False
    
def sign_message_rsa(message: str, private_key_path: str) -> str:
    private_key = load_rsa_private_key(private_key_path)
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature_rsa(message: str, signature_b64: str, public_key_path: str) -> bool:
    public_key = load_rsa_public_key(public_key_path)
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def sign_pdf(pdf_path: str, private_key_path: str, algorithm: str = "rsa") -> dict:
    with open(pdf_path, "rb") as f:
        pdf_content = f.read()
    pdf_hash = hashlib.sha256(pdf_content).digest()
    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    
    if algorithm == "rsa" and isinstance(priv_key, rsa.RSAPrivateKey):
        signature = priv_key.sign(
            pdf_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif algorithm == "ec" and isinstance(priv_key, ec.EllipticCurvePrivateKey):
        signature = priv_key.sign(pdf_hash, ec.ECDSA(hashes.SHA256()))
    elif algorithm == "ed25519" and isinstance(priv_key, ed25519.Ed25519PrivateKey):
        signature = priv_key.sign(pdf_hash)
    else:
        raise ValueError(f"Algorithm {algorithm} tidak didukung atau key tidak match")
    
    return {
        "filename": os.path.basename(pdf_path),
        "signature": base64.b64encode(signature).decode(),
        "algorithm": algorithm.upper(),
        "sha256_checksum": base64.b64encode(pdf_hash).decode()
    }

import hashlib

def setup_punkhazard_keys():
    folder = "punkhazard-keys"
    os.makedirs(folder, exist_ok=True)
    print("\n[PUNKHAZARD] Generating EC SECP256K1 keys")
    ec_priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    ec_pub = ec_priv.public_key()
    
    with open(f"{folder}/priv.pem", "wb") as f:
        f.write(ec_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(f"{folder}/pub.pem", "wb") as f:
        f.write(ec_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("[PUNKHAZARD] Generating ED25519 keys")
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    
    with open(f"{folder}/priv19.pem", "wb") as f:
        f.write(ed_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(f"{folder}/pub19.pem", "wb") as f:
        f.write(ed_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"Folder {folder} berhasil dibuat dengan semua keys!")
    print(f"priv.pem & pub.pem (EC SECP256K1)")
    print(f"priv19.pem & pub19.pem (ED25519)")


setup_punkhazard_keys()

# Create keys for users Rasya, Bima, Geral
users = ["Rasya", "Bima", "Geral"]
print("\n[STEP 1] Generating RSA keys untuk semua user")
for user in users:
    generate_rsa_keys(user)
print("\n[STEP 2] Generating EC keys untuk semua user")
for user in users:
    generate_ec_keys(user)
print("\n[STEP 3] Generating ED25519 keys untuk semua user")
for user in users:
    generate_ed25519_keys(user)

# Demonstration enkripsi and signing
print("\nDEMO: Enkripsi & Signing Pesan")

# Demonstration from Rasya to Bima using EC
print("\n[DEMO EC] Rasya -> Bima")
secret_message = "Hai bim"
print(f"Pesan asli: {secret_message}")

encrypted_data = encrypt_message(secret_message, "keys/Bima_pub.pem")
encrypted_msg_only = encrypted_data["encrypted_message"]
print(f"Encrypted: {encrypted_msg_only}")
print(f"Algorithm: {encrypted_data['algorithm']}")

signature_ec = sign_message_ec(encrypted_msg_only, "keys/Rasya_ec_priv.pem")
print(f"Signature (EC): {signature_ec}")

is_valid_ec = verify_signature_ec(encrypted_msg_only, signature_ec, "keys/Rasya_ec_pub.pem")
print(f"Signature valid: {is_valid_ec}")

if is_valid_ec:
    decrypted_msg = decrypt_message(encrypted_data, "keys/Bima_priv.pem")
    print(f"Decrypted: {decrypted_msg}")
else:
    print("Signature tidak valid! Pesan ditolak.")

# Demonstration from Bima to Rasya using ED25519
print("\n[DEMO ED25519] Bima -> Rasya")
message_ed = "Hai Juga"
print(f"Pesan asli: {message_ed}")

encrypted_data_ed = encrypt_message(message_ed, "keys/Rasya_pub.pem")
encrypted_msg_ed = encrypted_data_ed["encrypted_message"]
print(f"Encrypted: {encrypted_msg_ed}")

signature_ed = sign_message_ed25519(encrypted_msg_ed, "keys/Bima_ed25519_priv.pem")
print(f"Signature (ED25519): {signature_ed}")

is_valid_ed = verify_signature_ed25519(encrypted_msg_ed, signature_ed, "keys/Bima_ed25519_pub.pem")
print(f"Signature valid: {is_valid_ed}")

if is_valid_ed:
    decrypted_ed = decrypt_message(encrypted_data_ed, "keys/Rasya_priv.pem")
    print(f"Decrypted: {decrypted_ed}")
else:
    print("Signature tidak valid! Pesan ditolak.")

# Demonstration from Geral to Bima using RSA
print("\n[DEMO RSA] Geral -> Bima")
message_rsa = "Semangat Projectnya"
print(f"Pesan asli: {message_rsa}")

encrypted_data_rsa = encrypt_message(message_rsa, "keys/Bima_pub.pem")
encrypted_msg_rsa = encrypted_data_rsa["encrypted_message"]
print(f"Encrypted: {encrypted_msg_rsa}")

signature_rsa = sign_message_rsa(encrypted_msg_rsa, "keys/Geral_priv.pem")
print(f"Signature (RSA): {signature_rsa}")

is_valid_rsa = verify_signature_rsa(encrypted_msg_rsa, signature_rsa, "keys/Geral_pub.pem")
print(f"Signature valid: {is_valid_rsa}")

if is_valid_rsa:
    decrypted_rsa = decrypt_message(encrypted_data_rsa, "keys/Bima_priv.pem")
    print(f"Decrypted: {decrypted_rsa}")
else:
    print("Signature tidak valid! Pesan ditolak.")

test_data = {
    "relay_messages": {
        "ec_test": {
            "sender": "Rasya_EC",
            "recipient": "Bima",
            "encrypted_message": encrypted_msg_only,
            "signature": signature_ec,
            "description": "EC SECP256K1 signature test"
        },
        "ed25519_test": {
            "sender": "Bima_ED",
            "recipient": "Rasya",
            "encrypted_message": encrypted_msg_ed,
            "signature": signature_ed,
            "description": "ED25519 signature test"
        },
        "rsa_test": {
            "sender": "Geral",
            "recipient": "Bima",
            "encrypted_message": encrypted_msg_rsa,
            "signature": signature_rsa,
            "description": "RSA-PSS signature test"
        }
    },
    "verify_tests": {},
    "pdf_signatures": {},
    "verify_pdf_signatures": {}
}
print("\n[VERIFY TEST DATA] Generating signature verification data")

verify_messages = [
    ("Rasya_EC", "Hello from Rasya", "keys/Rasya_ec_priv.pem", "EC"),
    ("Bima_ED", "Test message from Bima", "keys/Bima_ed25519_priv.pem", "ED25519"),
    ("Geral", "RSA signature test", "keys/Geral_priv.pem", "RSA")
]

for username, msg, priv_key, algo in verify_messages:
    if algo == "EC":
        sig = sign_message_ec(msg, priv_key)
    elif algo == "ED25519":
        sig = sign_message_ed25519(msg, priv_key)
    else:
        sig = sign_message_rsa(msg, priv_key)
    
    test_data["verify_tests"][algo.lower()] = {
        "username": username,
        "message": msg,
        "signature": sig,
        "algorithm": algo,
        "description": f"Verify signature dengan algoritma {algo}"
    }
    print(f"{algo}: {username}")

print("\n[PDF SIGNATURE] Generating PDF signatures dengan 3 algoritma")

pdf_files = [f for f in os.listdir("data/pdfs") if f.endswith(".pdf")]
if not pdf_files:
    print("Tidak ada PDF di data/pdfs/, membuat dummy PDF")
    os.makedirs("data/pdfs", exist_ok=True)
    pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 44 >>\nstream\nBT\n/F1 24 Tf\n100 700 Td\n(If you know you know) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n0000000317 00000 n\ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n410\n%%EOF"
    
    with open("data/pdfs/test.pdf", "wb") as f:
        f.write(pdf_content)
    pdf_path = "data/pdfs/test.pdf"
else:
    pdf_path = f"data/pdfs/{pdf_files[0]}"

print(f"Menggunakan PDF: {pdf_path}")
with open(pdf_path, "rb") as f:
    pdf_content = f.read()

pdf_hash = hashlib.sha256(pdf_content).digest()
pdf_checksum_b64 = base64.b64encode(pdf_hash).decode()
pdf_signatures = [
    ("PunkEC", "punkhazard-keys/priv.pem", "punkhazard-keys/pub.pem", "EC", "SECP256K1"),
    ("PunkED", "punkhazard-keys/priv19.pem", "punkhazard-keys/pub19.pem", "ED25519", "ED25519"),
    ("Rasya", "keys/Rasya_priv.pem", "keys/Rasya_pub.pem", "RSA", "RSA-2048")
]

for username, priv_path, pub_path, algo, key_type in pdf_signatures:
    with open(priv_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    if algo == "RSA" and isinstance(priv_key, rsa.RSAPrivateKey):
        signature = priv_key.sign(
            pdf_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif algo == "EC" and isinstance(priv_key, ec.EllipticCurvePrivateKey):
        signature = priv_key.sign(pdf_hash, ec.ECDSA(hashes.SHA256()))
    elif algo == "ED25519" and isinstance(priv_key, ed25519.Ed25519PrivateKey):
        signature = priv_key.sign(pdf_hash)
    else:
        print(f"Error: Key type tidak match untuk {username}")
        continue
    signature_b64 = base64.b64encode(signature).decode()
    test_data["pdf_signatures"][algo.lower()] = {
        "username": username,
        "signature": signature_b64,
        "pdf_checksum": pdf_checksum_b64,
        "algorithm": algo,
        "key_type": key_type,
        "pdf_file": os.path.basename(pdf_path),
        "description": f"PDF signature menggunakan {key_type}",
        "private_key_path": priv_path,
        "public_key_path": pub_path
    }
    test_data["verify_pdf_signatures"][algo.lower()] = {
        "username": username,
        "signature": signature_b64,
        "pdf_checksum": pdf_checksum_b64,
        "algorithm": algo,
        "key_type": key_type,
        "description": f"Verifikasi PDF signature {key_type}"
    }
    print(f"{algo} ({key_type}): {username}")

with open("test_data.json", "w") as f:
    json.dump(test_data, f, indent=2)