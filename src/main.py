import hashing
import entropy
import auth
import os

def menu():
    user_secret = auth.generate_secret()
    
    while True:
        print("\nInteractive Security Menu")
        print("1. Calculate Hash (with Salt)")
        print("2. Integrity Check (Requires 2FA)")
        print("3. Calculate Entropy")
        print("4. Exit")
        
        choice = input("Select option: ").strip()

        if choice in ['1', '2', '3']:
            raw_filename = input("Enter filename: ").strip()
            fname = raw_filename.replace("'", "").replace('"', "")
            
            if not os.path.exists(fname):
                print(f"\n[ERROR] File '{fname}' not found!")
                continue 

            if choice == '1':
                algo = input("Choose algorithm (md5, sha1, sha256, sha3): ").strip().lower()
                # Function now returns both hash and salt
                file_hash, salt = hashing.get_file_hash(fname, algo)
                if file_hash and salt:
                    print(f"Hash ({algo}): {file_hash}")
                    print(f"Salt: {salt}")
                    hashing.save_hash(fname, file_hash, salt)
                    print("Hash and Salt saved successfully.")
                else:
                    print("Error: Could not calculate hash.")

            elif choice == '2':
                if auth.verify_2fa(user_secret):
                    algo = input("Enter algorithm used: ").strip().lower()
                    result = hashing.verify_integrity(fname, algo)
                    if result is True:
                        print("SUCCESS: Integrity verified.")
                    elif result is False:
                        print("WARNING: Integrity check failed!")
                    else:
                        print("Error: .hash file not found.")
                else:
                    print("Access Denied: Invalid OTP.")

            elif choice == '3':
                file_entropy = entropy.calculate_entropy(fname)
                if file_entropy is not None:
                    print(f"Shannon Entropy: {file_entropy:.4f}")

        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    menu()
