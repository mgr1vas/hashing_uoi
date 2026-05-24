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

# PART A: Hash & Salt (Αρχιτεκτονική Αποθήκευσης Διαπιστευτηρίων)
import hashlib

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    try:
        if salt is None:
            # Παράγει ένα κρυπτογραφικά ασφαλές τυχαίο salt 16 bytes ανά χρήστη.
            # Αποτρέπει επιθέσεις με Rainbow Tables και διασφαλίζει ότι ίδιοι κωδικοί παράγουν διαφορετικά hashes.
            salt_bytes = os.urandom(16)
        else:
            salt_bytes = bytes.fromhex(salt)
            
        hasher = hashlib.sha256()
        # Εισάγει το μοναδικό salt ΠΡΙΝ από τα bytes του κωδικού πρόσβασης στον αλγόριθμο SHA-256.
        # Αυτό εμποδίζει την εύκολη αντιστοίχιση προ-υπολογισμένων τιμών από επιτιθέμενους.
        hasher.update(salt_bytes)
        hasher.update(password.encode())
        
        return hasher.hexdigest(), salt_bytes.hex()
    except Exception:
        return "", ""

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    try:
        # Επανυπολογίζει το hash χρησιμοποιώντας το ίδιο αποθηκευμένο salt για να γίνει ντετερμινιστική σύγκριση.
        current_hash, _ = hash_password(password, salt)
        return current_hash == stored_hash
    except Exception:
        return False

# PART B: OTP & Ροή Εγγραφής Χρήστη
def admin_issue_otp(username: str) -> str:
    # Παράγει ένα τυχαίο token 8 χαρακτήρων (μίας χρήσης) που λειτουργεί ως out-of-band προ-έγκριση εγγραφής.
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
        # Αυστηρή επιβολή του περιορισμού "Μίας Χρήσης" για την αποτροπή επαναχρησιμοποίησης του token.
        if user_otp_data.get("used") is True:
            print("[ERROR] This OTP has already been used.")
            return False
            
        if otp_input.strip().upper() != user_otp_data.get("otp").upper():
            print("[ERROR] Invalid OTP supplied.")
            return False
            
        # Αλλαγή κατάστασης: Σημαίνει το token ως χρησιμοποιημένο ΠΡΙΝ καταγράψει τα στοιχεία του χρήστη.
        user_otp_data["used"] = True
        OTP_DB.write_text(json.dumps(otp_store, indent=2))
        
        users_data = json.loads(USERS_DB.read_text()) if USERS_DB.exists() else {}
        if username in users_data:
            print("[ERROR] Username is already registered.")
            return False
            
        p_hash, p_salt = hash_password(password)
        
        # Αποθηκεύει μόνο το παραγόμενο hash και το μοναδικό salt. Οι plaintext κωδικοί δεν αποθηκεύονται ποτέ.
        users_data[username] = {
            "password_hash": p_hash,
            "salt": p_salt,
            "created_at": datetime.now().isoformat()
        }
        USERS_DB.write_text(json.dumps(users_data, indent=2))
        
        # Ενεργοποιεί την αυτόματη δημιουργία ασύμμετρων κλειδιών RSA μόλις ολοκληρωθεί η έγκυρη εγγραφή.
        generate_user_keys(username)
        print(f"[SUCCESS] User '{username}' registered successfully!")
        return True
    except Exception as e:
        print(f"[ERROR] Registration failed: {e}")
        return False

# PART C: Αυθεντικοποίηση (Defense-in-Depth)
def authenticate_user(username: str, password: str) -> bool:
    try:
        if not USERS_DB.exists():
            print("[ERROR] Invalid login credentials")
            return False
            
        users_data = json.loads(USERS_DB.read_text())
        
        # Εμφανίζει ένα πανομοιότυπο, γενικό μήνυμα σφάλματος είτε υπάρχει ο χρήστης είτε όχι.
        # Αυτό αποτρέπει επιθέσεις User Enumeration (Απαρίθμηση Χρηστών), κρύβοντας την κατάσταση της βάσης.
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

# PART D: Ασύμμετρη Υποδομή Κλειδιών (RSA-2048)
def generate_user_keys(username: str):
    # Δημιουργεί ένα ασύμμετρο ζεύγος κλειδιών RSA με εκθέτη 65537 και ισχυρό μέγεθος modulus 2048-bit.
    pk = rsa.generate_private_key(65537, 2048, default_backend())
    # Εξάγει το Ιδιωτικό Κλειδί χωρίς κρυπτογράφηση (NoEncryption) για αυτοματοποιημένη προγραμματιστική υπογραφή.
    (KEYS_DIR / f"{username}_private.pem").write_bytes(
        pk.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.TraditionalOpenSSL,
                         serialization.NoEncryption())
    )
    # Εξάγει το αντίστοιχο Δημόσιο Κλειδί με τη standard μορφή SubjectPublicKeyInfo για χρήση στην επαλήθευση.
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

# PART E: Σύστημα Ελέγχου Anti-Replay (Nonces)
def generate_nonce() -> str:
    return secrets.token_hex(16)

def is_nonce_valid(nonce: str) -> bool:
    try:
        nonces = json.loads(NONCE_DB.read_text()) if NONCE_DB.exists() else []
        
        # Διασταυρώνει το nonce του αιτήματος με το ιστορικό αρχείο καταγραφής.
        # Ανιχνεύει και αποτρέπει Replay Attacks, όπου ένας επιθετικός υποκλέπτει και ξαναστέλνει ένα έγκυρο αίτημα.
        if nonce in nonces:
            print(f"[WARNING] Replay Attack Detected! Nonce '{nonce}' has already been processed.")
            return False
            
        # Βάζει το μοναδικό αναγνωριστικό στη "μαύρη λίστα" αμέσως μόλις ληφθεί για πρώτη φορά.
        nonces.append(nonce)
        NONCE_DB.write_text(json.dumps(nonces, indent=2))
        return True
    except Exception:
        return False

# PART F: Συμμετρική Αυθεντικοποιημένη Κρυπτογράφηση & Ψηφιακές Υπογραφές
def encrypt_file(data: bytes) -> tuple:
    try:
        # Παράγει ένα ισχυρό, πτητικό συμμετρικό κλειδί 32 bytes για τον αλγόριθμο AES-256.
        key = os.urandom(32)
        # Παράγει ένα απαραίτητο, μοναδικό διάνυσμα αρχικοποίησης (IV / nonce) 12 bytes για το GCM mode.
        # Αποτρέπει τη δημιουργία πανομοιότυπων μοτίβων (ciphertext) αν κρυπτογραφηθούν ίδια αρχεία.
        nonce_aes = os.urandom(12)
        
        # Χρησιμοποιεί AES-GCM, προσφέροντας Authenticated Encryption with Associated Data (AEAD).
        # Εγγυάται ταυτόχρονα την Εμπιστευτικότητα (κρυπτότητα) και την Ακεραιότητα/Αυθεντικότητα (ανίχνευση αλλοίωσης).
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce_aes, data, None)
        return ciphertext, key, nonce_aes
    except Exception:
        return b"", b"", b""

def decrypt_file(ciphertext: bytes, key: bytes, nonce_aes: bytes) -> bytes:
    try:
        aesgcm = AESGCM(key)
        # Η αποκρυπτογράφηση επαληθεύει αυτόματα το ενσωματωμένο AEAD authentication tag.
        # Πετάει exception αν έστω και ένα bit του αρχείου ή του IV έχει αλλοιωθεί, διασφαλίζοντας την ακεραιότητα.
        return aesgcm.decrypt(nonce_aes, ciphertext, None)
    except Exception:
        return b""

def sign_data(username: str, data: bytes, nonce: str) -> bytes:
    try:
        private_key = load_private_key(username)
        # Ενώνει τα δεδομένα του αρχείου με το nonce του αιτήματος σε ένα ενιαίο payload.
        # Αυτό "δένει" την ψηφιακή υπογραφή με τη συγκεκριμένη χρονική συναλλαγή/αίτημα.
        payload = data + nonce.encode()
        
        # Χρησιμοποιεί το ασφαλές πρότυπο RSA-PSS (πιθανοτική μορφοποίηση) με SHA-256 hashing.
        # Παρέχει μαθηματική απόδειξη προέλευσης και εγγυάται τη Μη-Αποποίηση (Non-Repudiation).
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
        # Χρησιμοποιεί το Δημόσιο Κλειδί του uploader για να επαληθεύσει την αυθεντικότητα της υπογραφής.
        # Αποτυγχάνει (InvalidSignature) αν τα δεδομένα, το nonce ή το κλειδί δεν ταιριάζουν απόλυτα.
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

# PART Z: Διασύνδεση Συστημάτων & Ενοποίηση
def upload_file(username: str, filepath: str):
    try:
        path = Path(filepath)
        if not path.exists():
            print("[ERROR] Local file path does not exist.")
            return
            
        data = path.read_bytes()
        nonce = generate_nonce()
        
        # Συμμόρφωση σειράς βημάτων: Η ψηφιακή υπογραφή δημιουργείται πάνω στα plaintext δεδομένα και το nonce πρώτα.
        signature = sign_data(username, data, nonce)
        
        # Πύλη ελέγχου anti-replay: Αν το nonce έχει ξαναχρησιμοποιηθεί, η εκτέλεση διακόπτεται αμέσως.
        if not is_nonce_valid(nonce):
            print("[ERROR] Request aborted due to nonce invalidation.")
            return
            
        ciphertext, key, nonce_aes = encrypt_file(data)
        (STORAGE_DIR / f"{path.name}.enc").write_bytes(ciphertext)
        
        # Τα raw δυαδικά στοιχεία (υπογραφές, κλειδιά, IVs) μετατρέπονται σε ασφαλείς συμβολοσειρές Base64 ASCII.
        # Αυτό επιτρέπει την ομαλή αποθήκευση δομημένων δεδομένων μέσα σε flat αρχεία JSON.
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
        
        # Εκτελεί ασύμμετρη επαλήθευση υπογραφής πάνω στο ανακτημένο plaintext.
        # Διασφαλίζει ότι το αρχείο δεν τροποποιήθηκε μετά το upload και ταυτοποιεί μαθηματικά τον uploader.
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
    print("Secure File Storage System")
    print("="*48)
    print(" 1. Register User (with OTP)")
    print(" 2. Login User")
    print(" 3. Secure Upload File")
    print(" 4. Secure Download File")
    print(" 0. Exit System")
    print("="*48)

def main():
    initialize_system()
    # Αρχικοποίηση μεταβλητής κατάστασης (session state).
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
                # Σύνδεση του ενεργού χρήστη με το runtime scope της εφαρμογής.
                logged_in_user = uname
                print(f"[SESSION] Active login session established for: {logged_in_user}")
        elif choice == '3':
            # Έλεγχος πρόσβασης (Access Control). Μπλοκάρει την αλληλεπίδραση αν δεν υπάρχει ενεργό session.
            if logged_in_user is None:
                print("[ERROR] Unauthenticated access. Please log in first.")
                continue
            fpath = input("Enter file path to upload: ").strip()
            upload_file(logged_in_user, fpath)
        elif choice == '4':
            # Έλεγχος πρόσβασης (Access Control). Μπλοκάρει την αλληλεπίδραση αν δεν υπάρχει ενεργό session.
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
