import math
from collections import Counter

def calculate_entropy(filename):
    try:
        # Ανοίγει το αρχείο σε binary mode ('rb') για την επεξεργασία του σε επίπεδο raw bytes.
        with open(filename, 'rb') as f:
            data = f.read()
        if not data: return 0.0 # Αν το αρχείο είναι κενό, η εντροπία είναι μηδέν.
        file_size = len(data)
        # Καταγράφει τις εμφανίσεις κάθε μεμονωμένου byte (0-255) για τη δημιουργία της κατανομής συχνότητας.
        byte_counts = Counter(data)
        entropy = 0
        for count in byte_counts.values():
            # Υπολογίζει την πιθανότητα p(x) εμφάνισης του τρέχοντος byte μέσα στο αρχείο.
            p_x = count / file_size
            # Προσθέτει στο τελικό άθροισμα με βάση τον μαθηματικό τύπο του Shannon Entropy.
            # Μέτρο τυχαιότητας: Υψηλή εντροπία δείχνει ισχυρή κρυπτογράφηση ή συμπίεση δεδομένων.
            entropy -= p_x * math.log2(p_x)
        return entropy
    except FileNotFoundError:
        return None
