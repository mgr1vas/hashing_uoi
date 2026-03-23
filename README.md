# Information Systems Security - 1st Assignment
# Name/Surname: Marios Grivas
# ID: 2931
# E-mail: int02931@uoi.gr

This project is the first assignment for the **Information Systems Security** course at the **University of Ioannina**, Department of Informatics & Telecommunications. It implements a security utility tool focused on data integrity, entropy analysis, and two-factor authentication (2FA).

## Features

The application is divided into three main functional parts:

### Part A: Hashing & Integrity Check
* **Multi-Algorithm Support**: Calculates hashes using MD5, SHA-1, SHA-256, and SHA-3 (Keccak).
* **Binary Processing**: Reads files in binary mode to support any file type (PDF, EXE, images, etc.).
* **Integrity Verification**: Saves the calculated hash to a `.hash` file and compares it later to detect if a file has been altered or modified.

### Part B: Shannon Entropy Analysis
* **Randomness Measurement**: Calculates the entropy of a file at the byte level (0-255).
* **Data Characterization**: Identifies if a file is likely encrypted (entropy values near 8) or simple text (lower entropy values).
* **Mathematical Formula**: Implements the Shannon Entropy formula: $H=-\sum p(x_{i})log_{2}p(x_{i})$.

### Part C: Two-Factor Authentication (2FA)
* **OTP Generation**: Uses a secret key to generate a dynamic One-Time Password (OTP).
* **Access Control**: Protects critical operations, such as integrity checks, by requiring a valid 6-digit code before execution.

### Questions and Answers
- Γιατί ένα encrypted αρχείο έχει entropy κοντά στο 8;
    - Η κρυπτογράφηση έχει ως στόχο να κάνει τα δεδομένα να φαίνονται εντελώς τυχαία (noise). Σε ένα ιδανικά κρυπτογραφημένο αρχείο, κάθε μία από τις 256 δυνατές τιμές byte εμφανίζεται με την ίδια ακριβώς πιθανότητα. Όταν η πιθανότητα είναι ομοιόμορφη, η εντροπία Shannon φτάνει στο μέγιστο όριό της, που είναι το log2​(256)=8.
- Γιατί ένα απλό text αρχείο έχει μικρότερη εντροπία;
    - Σε ένα αρχείο κειμένου, τα δεδομένα είναι προβλέψιμα και μη ομοιόμορφα. Χρησιμοποιείται μόνο ένα μικρό υποσύνολο των διαθέσιμων bytes (π.χ. μόνο ASCII χαρακτήρες, κενά, αλλαγές γραμμής). Επειδή ορισμένα bytes εμφανίζονται πολύ συχνά (π.χ. το "e" ή το κενό) και άλλα καθόλου, η "αβεβαιότητα" των δεδομένων μειώνεται, οδηγώντας σε χαμηλότερη τιμή εντροπίας.

## Project Structure

```text
.
├── src/
│   ├── main.py         
│   ├── hashing.py
│   ├── entropy.py       
├── README.md        
├── requirements.txt    
└── .gitignore           
