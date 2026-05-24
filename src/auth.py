import secrets
import hashlib

def generate_secret():
    # Χρησιμοποιεί μια κρυπτογραφικά ασφαλή γεννήτρια τυχαίων αριθμών (CSRNG).
    # Παράγει ένα μοναδικό τυχαίο seed 16 bytes για το δυναμικό σύστημα 2FA.
    return secrets.token_hex(16)

def get_otp(secret):
    # Προσομοιώνει ένα δυναμικό One-Time Password κάνοντας hash το μυστικό κλειδί.
    # Το hex string μετατρέπεται σε ακέραιο και αποκόπτονται τα πρώτα 6 ψηφία.
    return str(int(hashlib.sha256(secret.encode()).hexdigest(), 16))[:6]

def verify_2fa(secret): # Ελέγχει αν ο χρήστης εισάγει τον σωστό OTP.
    correct_otp = get_otp(secret)
    print(f"\n[2FA System] Your current OTP is: {correct_otp}")
    user_input = input("Enter the 6-digit OTP to proceed: ")
    # Επιβάλλει έλεγχο προσωρινού κωδικού για την αποτροπή επιθέσεων επανάληψης (replay attacks).
    return user_input == correct_otp # Επιστρέφει True αν ο χρήστης εισάγει τον σωστό OTP, αλλιώς False.
