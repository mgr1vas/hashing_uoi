import hashing
import entropy
import auth
import os

def menu():
    # Creation of a user-specific secret for 2FA. In a real application, this would be securely stored and associated with the user account.
    user_secret = auth.generate_secret()
    
    while True:
        # DEBUGGING INFO: Prints the current working directory to help identify where the script is running
        print(f"\n[DEBUG] Current Directory: {os.getcwd()}")
        print(f"[DEBUG] Files I can see: {os.listdir('.')}")
        
        print("\nInteractive Menu")
        print("1. Calculate Hash")
        print("2. Integrity Check (Requires 2FA)")
        print("3. Calculate Entropy")
        print("4. Exit")
        
        choice = input("Select option: ").strip()

        if choice in ['1', '2', '3']:
            fname = input("Enter filename: ").strip()
            
            # DEBUGGING INFO: Check if file exists before proceeding
            if not os.path.exists(fname):
                print(f"\n[ERROR] File '{fname}' not found!")
                print(f"[DEBUG] Files in this folder: {os.listdir('.')}")
                continue # Return to menu if file not found
        if choice == '1':
            algo = input("Choose algorithm (md5, sha1, sha256, sha3): ").strip().lower()
            h = hashing.get_file_hash(fname, algo)
            if h:
                print(f"Hash ({algo}): {h}")
                hashing.save_hash(fname, h)
                print("Hash saved successfully.")
            else:
                print("Error: Could not calculate hash.")
        elif choice == '2':
            if auth.verify_2fa(user_secret):
                algo = input("Enter algorithm used for the original hash: ").strip().lower()
                result = hashing.verify_integrity(fname, algo)
                if result is True:
                    print("SUCCESS: The file has not been modified.")
                elif result is False:
                    print("WARNING: The file has been altered!")
                else:
                    print("Error: Stored hash file (.hash) not found.")
            else:
                print("Access Denied: Wrong OTP.")
        elif choice == '3':
            ent = entropy.calculate_entropy(fname)
            if ent is not None:
                print(f"Shannon Entropy: {ent:.4f}")
                if ent > 7.5:
                    print("Note: High randomness (likely encrypted/compressed).")
                else:
                    print("Note: Low randomness (likely simple data).")
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
if __name__ == "__main__":
    menu()
