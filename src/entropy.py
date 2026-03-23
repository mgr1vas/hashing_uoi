import math
from collections import Counter

def calculate_entropy(filename):
    try:
        with open(filename, 'rb') as f: # Binary mode [cite: 31, 100]
            data = f.read()
        if not data: return 0.0

        file_size = len(data)
        byte_counts = Counter(data) # Count occurrences of each byte [cite: 33, 101]
        
        entropy = 0
        for count in byte_counts.values():
            p_x = count / file_size # Calculate probability p(x) [cite: 34, 102, 103, 104]
            entropy -= p_x * math.log2(p_x) # Shannon formula [cite: 36, 93, 110]
        return entropy
    except FileNotFoundError:
        return None