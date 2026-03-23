import hashing
import entropy
import auth

def menu():
    user_secret = auth.generate_secret()
    
    while True:
        print("\n--- Interactive Menu ---") [cite: 56, 118]
        print("1. Calculate Hash") [cite: 120]
        print("2. Integrity Check (Requires 2FA)") [cite: 121]
        print("3. Calculate Entropy") [cite: 122]
        print("4. Exit") [cite: 124]
        
        choice = input("Select option: ")

        if choice == '1':
            fname = input("Enter filename: ")
            algo = input("Choose algorithm (md5, sha1, sha256, sha3): ")
            h = hashing.get_file_hash(fname, algo)
            if h:
                print(f"Hash ({algo}): {h}")
                hashing.save_hash(fname, h)
                print("Hash saved successfully.")
            else:
                print("Error: File not found.")

        elif choice == '2':
            # Critical action: requires 2FA first [cite: 54, 123]
            if auth.verify_2fa(user_secret):
                fname = input("Enter filename to verify: ")
                algo = input("Enter algorithm used: ")
                result = hashing.verify_integrity(fname, algo)
                if result is True:
                    print("SUCCESS: The file has not been modified.") [cite: 26, 89]
                elif result is False:
                    print("WARNING: The file has been altered!") [cite: 26, 90]
                else:
                    print("Error: Stored hash file not found.")
            else:
                print("Access Denied: Wrong OTP.") [cite: 53]

        elif choice == '3':
            fname = input("Enter filename: ")
            ent = entropy.calculate_entropy(fname)
            if ent is not None:
                print(f"Shannon Entropy: {ent:.4f}") [cite: 37]
                if ent > 7.5:
                    print("Note: High randomness (likely encrypted/compressed).") [cite: 38]
                else:
                    print("Note: Low randomness (likely simple data).") [cite: 38]

        elif choice == '4':
            print("Exiting...")
            break

if __name__ == "__main__":
    menu()