import hashlib

def get_file_hash(filename, algorithm='sha256'):
    algorithms = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha3': hashlib.sha3_256()
    }
    hash_obj = algorithms.get(algorithm.lower())
    if not hash_obj: return None

    try:
        with open(filename, 'rb') as f: # Read in binary mode [cite: 13, 63]
            while chunk := f.read(4096):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except FileNotFoundError:
        return None

def save_hash(filename, hash_value):
    with open(f"{filename}.hash", "w") as f: # Save to filename.hash [cite: 24, 82]
        f.write(hash_value)

def verify_integrity(filename, algorithm):
    current_hash = get_file_hash(filename, algorithm)
    try:
        with open(f"{filename}.hash", "r") as f:
            stored_hash = f.read().strip()
        return current_hash == stored_hash
    except FileNotFoundError:
        return None