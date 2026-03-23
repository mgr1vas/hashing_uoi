import secrets
import hashlib

def generate_secret():
    return secrets.token_hex(16) # Generate secret key

def get_otp(secret):
    # Simple simulation of a dynamic OTP
    return str(int(hashlib.sha256(secret.encode()).hexdigest(), 16))[:6]

def verify_2fa(secret):
    correct_otp = get_otp(secret)
    print(f"\n[2FA System] Your current OTP is: {correct_otp}") # Simulated display
    user_input = input("Enter the 6-digit OTP to proceed: ")
    return user_input == correct_otp # Verification
