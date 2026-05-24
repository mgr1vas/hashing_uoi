import hashlib
import os

def get_file_hash(filename, algorithm):
    try:
        # Παράγει ένα κρυπτογραφικά ασφαλές τυχαίο salt 16 bytes με την os.urandom().
        # Αποτρέπει επιθέσεις με Rainbow Tables και εγγυάται διαφορετικό hash για ίδια αρχεία.
        salt = os.urandom(16)
        
        algo_map = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha3': hashlib.sha3_256()
        }
        
        if algorithm not in algo_map: # Ελέγχει αν ο επιλεγμένος αλγόριθμος είναι έγκυρος και υποστηριζόμενος.
            return None, None
            
        hasher = algo_map[algorithm]
        # Εισάγει το salt στον κρυπτογραφικό αλγόριθμο ΠΡΙΝ διαβαστούν τα δεδομένα του αρχείου.
        # Αυτό αλλάζει πλήρως την αρχική εσωτερική κατάσταση (internal state) της συνάρτησης hash.
        hasher.update(salt)
        
        with open(filename, 'rb') as f:
            # Διαβάζει το αρχείο σε block των 4096 bytes για την αποφυγή υπερχείλισης της μνήμης RAM.
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
                
        return hasher.hexdigest(), salt.hex() # Επιστρέφει το hash ως hex string και το salt επίσης σε hex για εύκολη αποθήκευση.
    except Exception:
        return None, None

def save_hash(filename, hash_value, salt_value):
    try:
        # Αποθηκεύει το hash και το salt διαχωρισμένα με άνω-κάτω τελεία.
        # Το salt πρέπει να αποθηκευτεί δημόσια για να είναι εφικτός ο μελλοντικός έλεγχος.
        with open(f"{filename}.hash", "w") as f:
            f.write(f"{hash_value}:{salt_value}")
    except Exception as e:
        print(f"Error saving file: {e}")

def verify_integrity(filename, algorithm): # Ελέγχει αν το αρχείο έχει υποστεί μη εξουσιοδοτημένη αλλοίωση συγκρίνοντας το νέο hash με το αποθηκευμένο.
    try:
        with open(f"{filename}.hash", "r") as f:
            data = f.read().strip().split(":")
            if len(data) != 2: # Ελέγχει αν το αποθηκευμένο hash αρχείο έχει τη σωστή μορφή (hash:salt).
                return False
            stored_hash, stored_salt_hex = data
            
        # Μετατρέπει το αποθηκευμένο hex string του salt ξανά σε raw bytes για εκτέλεση.
        salt = bytes.fromhex(stored_salt_hex)
        
        algo_map = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha3': hashlib.sha3_256()
        }
        
        hasher = algo_map[algorithm]
        # Εφαρμόζει πρώτα το αποθηκευμένο salt για να είναι ο επανυπολογισμός ντετερμινιστικός.
        hasher.update(salt)
        
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""): # Διαβάζει το αρχείο σε block των 4096 bytes για την αποφυγή υπερχείλισης της μνήμης RAM.
                hasher.update(chunk)
        
        # Ελέγχει την ακεραιότητα (Integrity) συγκρίνοντας το νέο hash με το αποθηκευμένο.
        # Ανιχνεύει αν το αρχείο έχει υποστεί μη εξουσιοδοτημένη αλλοίωση ή bit rot.
        return hasher.hexdigest() == stored_hash
    except Exception:
        return None
