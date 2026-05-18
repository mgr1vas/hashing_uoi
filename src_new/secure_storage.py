#!/usr/bin/env python3
import os
import json
import secrets
import base64
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# CONSTANTS
USERS_DB = Path('users.json')
STORAGE_DIR = Path('secure_storage')
KEYS_DIR = Path('keys')
NONCE_DB = Path('nonces.json')
OTP_DB = Path('otp_store.json')

def initialize_system():
    STORAGE_DIR.mkdir(exist_ok=True)
    KEYS_DIR.mkdir(exist_ok=True)
    for f, default in [(USERS_DB, {}), (NONCE_DB, []), (OTP_DB, {})]:
        if not f.exists():
            f.write_text(json.dumps(default))

# PART A: Hash & Salt (Credential Storage Architecture)
import hashlib

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    try:
        if salt is None:
            # Generates a cryptographically secure random 16-byte salt per user.
            # Mitigates Rainbow Table attacks and ensures identical passwords result in distinct hashes.
            salt_bytes = os.urandom(16)
        else:
            salt_bytes = bytes.fromhex(salt)
            
        hasher = hashlib.sha256()
        # Prepends the unique salt before feeding the password bytes into the SHA-256 pipeline.
        # This prevents trivial pre-computation matching by attackers.
        hasher.update(salt_bytes)
        hasher.update(password.encode())
        
        return hasher.hexdigest(), salt_bytes.hex()
    except Exception:
        return "", ""

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    try:
        # Recomputes the hash using the identical stored salt to achieve a deterministic comparison.
        current_hash, _ = hash_password(password, salt)
        return current_hash == stored_hash
    except Exception:
        return False

# PART B: OTP & User Registration Flow
def admin_issue_otp(username: str) -> str:
    # Generates an 8-character single-use token providing out-of-band pre-authorization.
    otp = secrets.token_hex(4).upper()
    store = json.loads(OTP_DB.read_text())
    store[username] = {
        "otp": otp,
        "issued_at": datetime.now().isoformat(),
        "used": False
    }
    OTP_DB.write_text(json.dumps(store, indent=2))
    print(f" [ADMIN] OTP issued for '{username}': {otp}")
    return otp

def register_user(username: str, otp_input: str, password: str) -> bool:
    try:
        if not OTP_DB.exists():
            print("[ERROR] OTP Database file is missing.")
            return False
        otp_store = json.loads(OTP_DB.read_text())
        
        if username not in otp_store:
            print("[ERROR] No OTP record found for this username.")
            return False
            
        user_otp_data = otp_store[username]
        # Strict enforcement of the "One-Time" constraint to mitigate token reuse risks.
        if user_otp_data.get("used") is True:
            print("[ERROR] This OTP has already been used.")
            return False
            
        if otp_input.strip().upper() != user_otp_data.get("otp").upper():
            print("[ERROR] Invalid OTP supplied.")
            return False
            
        # State-change mapping. Marks the token consumed before writing user records.
        user_otp_data["used"] = True
        OTP_DB.write_text(json.dumps(otp_store, indent=2))
        
        users_data = json.loads(USERS_DB.read_text()) if USERS_DB.exists() else {}
        if username in users_data:
            print("[ERROR] Username is already registered.")
            return False
            
        p_hash, p_salt = hash_password(password)
        
        # Persists only the derivative hash and unique salt. Plaintext credentials are never saved.
        users_data[username] = {
            "password_hash": p_hash,
            "salt": p_salt,
            "created_at": datetime.now().isoformat()
        }
        USERS_DB.write_text(json.dumps(users_data, indent=2))
        
        # Triggers automated asymmetric key generation upon verified registration bounds.
        generate_user_keys(username)
        print(f"[SUCCESS] User '{username}' registered successfully!")
        return True
    except Exception as e:
        print(f"[ERROR] Registration failed: {e}")
        return False

# PART C: Authentication
def authenticate_user(username: str, password: str) -> bool:
    try:
        if not USERS_DB.exists():
            print("[ERROR] Invalid login credentials")
            return False
            
        users_data = json.loads(USERS_DB.read_text())
        
        # Surface an identical, generic error message whether the user exists or not.
        # This addresses User Enumeration side-channel attacks, hiding database state from attackers.
        if username not in users_data:
            print("[ERROR] Invalid login credentials")
            return False
            
        user_info = users_data[username]
        stored_hash = user_info["password_hash"]
        stored_salt = user_info["salt"]
        
        if verify_password(password, stored_hash, stored_salt):
            return True
        else:
            print("[ERROR] Invalid login credentials")
            return False
    except Exception:
        return False

# PART D: Asymmetric Key Infrastructure (RSA-2048)
def generate_user_keys(username: str):
    # Establishes asymmetric RSA key pair with standard public exponent 65537 and strong 2048-bit modulus length.
    pk = rsa.generate_private_key(65537, 2048, default_backend())
    # Exports the Private Key securely with No Encryption (unencrypted format for automated programmatic signing tasks).
    (KEYS_DIR / f"{username}_private.pem").write_bytes(
        pk.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.TraditionalOpenSSL,
                         serialization.NoEncryption())
    )
    # Exports the corresponding Public Key using the standard SubjectPublicKeyInfo format for general validation distribution.
    (KEYS_DIR / f"{username}_public.pem").write_bytes(
        pk.public_key().public_bytes(serialization.Encoding.PEM,
                                     serialization.PublicFormat.SubjectPublicKeyInfo)
    )

def load_private_key(username: str):
    return serialization.load_pem_private_key(
        (KEYS_DIR / f"{username}_private.pem").read_bytes(),
        password=None, backend=default_backend()
    )

def load_public_key(username: str):
    return serialization.load_pem_public_key(
        (KEYS_DIR / f"{username}_public.pem").read_bytes(),
        backend=default_backend()
    )

# PART E: Nonce / Anti-Replay Validation System
def generate_nonce() -> str:
    return secrets.token_hex(16)

def is_nonce_valid(nonce: str) -> bool:
    try:
        nonces = json.loads(NONCE_DB.read_text()) if NONCE_DB.exists() else []
        
        # Cross-references request nonce against an historical database array.
        # Detects and prevents Message Replay Attacks where an attacker intercepts and resubmits a valid payload.
        if nonce in nonces:
            print(f"[WARNING] Replay Attack Detected! Nonce '{nonce}' has already been processed.")
            return False
            
        # Blacklists the unique identifier immediately upon first clean arrival.
        nonces.append(nonce)
        NONCE_DB.write_text(json.dumps(nonces, indent=2))
        return True
    except Exception:
        return False

# PART F: Symmetric Authenticated Encryption & Digital Signatures
def encrypt_file(data: bytes) -> tuple:
    try:
        # Generates a cryptographically strong, volatile 32-byte symmetric key for AES-256.
        key = os.urandom(32)
        # Generates an essential, unique 12-byte initialization vector (nonce) for GCM mode.
        # Prevents deterministic patterns if identical plaintext content blocks are encrypted.
        nonce_aes = os.urandom(12)
        
        # Utilizes AES-GCM mode providing Authenticated Encryption with Associated Data (AEAD).
        # Simultaneously guarantees Confidentiality (privacy) and Integrity/Authenticity (tamper detection).
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce_aes, data, None)
        return ciphertext, key, nonce_aes
    except Exception:
        return b"", b"", b""

def decrypt_file(ciphertext: bytes, key: bytes, nonce_aes: bytes) -> bytes:
    try:
        aesgcm = AESGCM(key)
        # Decryption automatically validates the implicit AEAD authentication tag.
        # Throws an exception if any ciphertext or IV bit was modified, ensuring strict data integrity.
        return aesgcm.decrypt(nonce_aes, ciphertext, None)
    except Exception:
        return b""

def sign_data(username: str, data: bytes, nonce: str) -> bytes:
    try:
        private_key = load_private_key(username)
        # Binds the file content with the application nonce string into an immutable payload.
        # This ties the cryptographic signature context directly to this specific session transaction request.
        payload = data + nonce.encode()
        
        # Uses secure RSA-PSS probabilistic padding paired with SHA-256 hashing.
        # Provides mathematical proof of origin and guarantees Non-Repudiation (uploader cannot deny action).
        return private_key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception:
        return b""

def verify_signature(username: str, data: bytes, nonce: str, sig: bytes) -> bool:
    try:
        public_key = load_public_key(username)
        payload = data + nonce.encode()
        # Uses the uploader's Public Key to cryptographically authenticate authorship.
        # Throws InvalidSignature if the file data, nonce value, or key pairing do not match perfectly.
        public_key.verify(
            sig,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        print("[WARNING] Invalid cryptographic signature detected!")
        return False

# PART Z: System Pipelines & Storage Integration
def upload_file(username: str, filepath: str):
    try:
        path = Path(filepath)
        if not path.exists():
            print("[ERROR] Local file path does not exist.")
            return
            
        data = path.read_bytes()
        nonce = generate_nonce()
        
        # Sequence ordering compliance. Signature is drawn across plaintext content and nonce first.
        signature = sign_data(username, data, nonce)
        
        # Anti-replay enforcement gateway. If nonce assertion fails, execution aborts immediately.
        if not is_nonce_valid(nonce):
            print("[ERROR] Request aborted due to nonce invalidation.")
            return
            
        ciphertext, key, nonce_aes = encrypt_file(data)
        (STORAGE_DIR / f"{path.name}.enc").write_bytes(ciphertext)
        
        # Raw binary cryptographic components (signatures, keys, IVs) are converted to safe,
        # ASCII-compliant Base64 strings to support cross-platform structure persistence inside flat JSON logs.
        metadata = {
            "signature": base64.b64encode(signature).decode('utf-8'),
            "key": base64.b64encode(key).decode('utf-8'),
            "nonce_aes": base64.b64encode(nonce_aes).decode('utf-8'),
            "nonce": nonce,
            "uploader": username,
            "original_filename": path.name,
            "timestamp": datetime.now().isoformat()
        }
        (STORAGE_DIR / f"{path.name}.json").write_text(json.dumps(metadata, indent=2))
        print(f"[SUCCESS] File '{path.name}' securely uploaded.")
    except Exception:
        pass

def download_file(username: str, filename: str):
    try:
        json_path = STORAGE_DIR / f"{filename}.json"
        enc_path = STORAGE_DIR / f"{filename}.enc"
        if not json_path.exists() or not enc_path.exists():
            print("[ERROR] Secure storage files or metadata missing for this item.")
            return
            
        metadata = json.loads(json_path.read_text())
        ciphertext = enc_path.read_bytes()
        
        key = base64.b64decode(metadata["key"])
        nonce_aes = base64.b64decode(metadata["nonce_aes"])
        signature = base64.b64decode(metadata["signature"])
        nonce = metadata["nonce"]
        
        plaintext = decrypt_file(ciphertext, key, nonce_aes)
        
        # Executes asymmetric signature verification on the recovered plaintext.
        # This guarantees the item was not modified post-upload and mathematically identifies the uploader.
        if verify_signature(metadata["uploader"], plaintext, nonce, signature):
            out_path = Path(f"downloaded_{metadata['original_filename']}")
            out_path.write_bytes(plaintext)
            print(f"[SUCCESS] File downloaded and verified as '{out_path.name}'.")
        else:
            print("[ERROR] Cryptographic signature check completely failed!")
    except Exception:
        pass

def show_menu():
    print("\n" + "="*48)
    print("           Secure File Storage System           ")
    print("="*48)
    print(" 1. Register User (with OTP)")
    print(" 2. Login User")
    print(" 3. Secure Upload File")
    print(" 4. Secure Download File")
    print(" 0. Exit System")
    print("="*48)

def main():
    initialize_system()
    # Session state tracking variable initialization.
    logged_in_user = None
    
    while True:
        show_menu()
        print(" [Admin Helper: Press 9 to issue a simulation OTP]")
        choice = input("Select option: ").strip()
        
        if choice == '1':
            uname = input("Enter new username: ").strip()
            otp_in = input("Enter your 8-digit OTP code: ").strip()
            pwd = input("Enter account password: ").strip()
            register_user(uname, otp_in, pwd)
        elif choice == '2':
            uname = input("Enter username: ").strip()
            pwd = input("Enter password: ").strip()
            if authenticate_user(uname, pwd):
                # Binding identity state context to active execution scope.
                logged_in_user = uname
                print(f"[SESSION] Active login session established for: {logged_in_user}")
        elif choice == '3':
            # Strict Access Control Check. Blocks data interaction pathways unless session identity is active.
            if logged_in_user is None:
                print("[ERROR] Unauthenticated access. Please log in first.")
                continue
            fpath = input("Enter file path to upload: ").strip()
            upload_file(logged_in_user, fpath)
        elif choice == '4':
            # Strict Access Control Check. Blocks data interaction pathways unless session identity is active.
            if logged_in_user is None:
                print("[ERROR] Unauthenticated access. Please log in first.")
                continue
            fname = input("Enter filename to download (e.g., sample.txt): ").strip()
            download_file(logged_in_user, fname)
        elif choice == '9':
            uname = input("Enter target username for simulation OTP: ").strip()
            admin_issue_otp(uname)
        elif choice == '0':
            print("Shutting down secure shell session. Goodbye!")
            break
        else:
            print("[ERROR] Unknown menu instruction selection.")

if __name__ == "__main__":
    main()
