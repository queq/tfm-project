from collections import Counter
from math import log

def shannon(string):
    counts = Counter(string)

    # del counts['a']
    for k in counts.keys():
        if k not in 'bc':
            print(k)
            
    frequencies = ((i / len(string)) for i in counts.values())
    return - sum(f * log(f, 2) for f in frequencies)
    # print(frequencies)

print(shannon("aabaa"))