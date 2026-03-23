import hashing
import entropy
import auth

def menu():
    user_secret = auth.generate_secret()
    
    while True:
        print("\n Interactive Menu")
        print("1. Calculate Hash")
        print("2. Integrity Check (Requires 2FA)")
        print("3. Calculate Entropy")
        print("4. Exit")
        
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
            # Critical action: requires 2FA first
            if auth.verify_2fa(user_secret):
                fname = input("Enter filename to verify: ")
                algo = input("Enter algorithm used: ")
                result = hashing.verify_integrity(fname, algo)
                if result is True:
                    print("SUCCESS: The file has not been modified.")
                elif result is False:
                    print("WARNING: The file has been altered!")
                else:
                    print("Error: Stored hash file not found.")
            else:
                print("Access Denied: Wrong OTP.")

        elif choice == '3':
            fname = input("Enter filename: ")
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

if __name__ == "__main__":
    menu()
