import hashing
import entropy
import auth
import os

def menu():
    # Generate a secret key for 2FA at the start of the session
    user_secret = auth.generate_secret()
    
    while True:
        print("\nInteractive Security Menu")
        print("1. Calculate Hash")
        print("2. Integrity Check (Requires 2FA)")
        print("3. Calculate Entropy")
        print("4. Exit")
        
        # Get user menu choice and clean whitespace
        choice = input("Select option: ").strip()

        # Handle options that require a filename input
        if choice in ['1', '2', '3']:
            # Sanitize filename input for Linux (remove quotes and extra spaces)
            raw_filename = input("Enter filename: ").strip()
            fname = raw_filename.replace("'", "").replace('"', "")
            # Verify file existence before proceeding
            if not os.path.exists(fname):
                print(f"\n[ERROR] File '{fname}' not found!")
                print(f"[DEBUG] Working Directory: {os.getcwd()}")
                print(f"[DEBUG] Available files: {os.listdir('.')}")
                continue 
            # Option 1: Hash Calculation and Storage
            if choice == '1':
                algo = input("Choose algorithm (md5, sha1, sha256, sha3): ").strip().lower()
                file_hash = hashing.get_file_hash(fname, algo)
                if file_hash:
                    print(f"Hash ({algo}): {file_hash}")
                    hashing.save_hash(fname, file_hash)
                    print("Hash saved successfully to .hash file.")
                else:
                    print("Error: Could not calculate hash.")
            # Option 2: Integrity Verification with 2FA
            elif choice == '2':
                # Trigger 2FA authentication before sensitive operation
                if auth.verify_2fa(user_secret):
                    algo = input("Enter algorithm used for the original hash: ").strip().lower()
                    result = hashing.verify_integrity(fname, algo)
                    if result is True:
                        print("SUCCESS: Integrity verified. The file is original.")
                    elif result is False:
                        print("WARNING: Integrity check failed! The file has been altered.")
                    else:
                        print("Error: Reference .hash file was not found.")
                else:
                    print("Access Denied: Invalid OTP.")
            # Option 3: Shannon Entropy Analysis
            elif choice == '3':
                file_entropy = entropy.calculate_entropy(fname)
                if file_entropy is not None:
                    print(f"Shannon Entropy: {file_entropy:.4f}")
                    # Interpretation of entropy value
                    if file_entropy > 7.5:
                        print("Status: High randomness (Likely encrypted or compressed).")
                    else:
                        print("Status: Low randomness (Likely structured/plain data).")
        # Option 4: Exiting Application
        elif choice == '4':
            print("Exiting application...")
            break
        else:
            print("Invalid selection. Please try again.")

if __name__ == "__main__":
    menu()
