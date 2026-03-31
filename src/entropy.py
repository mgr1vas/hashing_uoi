import math
from collections import Counter

def calculate_entropy(filename):
    try:
        with open(filename, 'rb') as f: # Binary mode
            data = f.read()
        if not data: return 0.0
        file_size = len(data)
        byte_counts = Counter(data) # Count occurrences of each byte
        entropy = 0
        for count in byte_counts.values():
            p_x = count / file_size # Calculate probability p(x)
            entropy -= p_x * math.log2(p_x) # Shannon formula
        return entropy
    except FileNotFoundError:
        return None
