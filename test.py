from collections import Counter
from math import log

def shannon(string):
    counts = Counter(string)
    frequencies = ((i / len(string)) for i in counts.values())

    print(frequencies)

shannon("Hello, World!")