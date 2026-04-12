import hashlib
import os

def get_file_hash(filename, algorithm):
    try:
        # Generate random 16-byte salt
        salt = os.urandom(16)
        
        algo_map = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha3': hashlib.sha3_256()
        }
        
        if algorithm not in algo_map:
            return None, None
            
        hasher = algo_map[algorithm]
        # Update hasher with salt first
        hasher.update(salt)
        
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
                
        return hasher.hexdigest(), salt.hex()
    except Exception:
        return None, None

def save_hash(filename, hash_value, salt_value):
    try:
        # Store hash and salt separated by a colon
        with open(f"{filename}.hash", "w") as f:
            f.write(f"{hash_value}:{salt_value}")
    except Exception as e:
        print(f"Error saving file: {e}")

def verify_integrity(filename, algorithm):
    try:
        with open(f"{filename}.hash", "r") as f:
            data = f.read().strip().split(":")
            if len(data) != 2:
                return False
            stored_hash, stored_salt_hex = data
            
        salt = bytes.fromhex(stored_salt_hex)
        
        algo_map = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha3': hashlib.sha3_256()
        }
        
        hasher = algo_map[algorithm]
        # Use the stored salt for re-calculation
        hasher.update(salt)
        
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest() == stored_hash
    except Exception:
        return None
