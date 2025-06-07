"""
🔐 Cryptology Toolkit
Author: Your Name
Description:
    A professional Python toolset for encrypting and decrypting messages using:
    - Caesar Cipher (with cracking)
    - Atbash Cipher
    - Vigenère Cipher (with key prediction using frequency analysis)
"""

import string
from collections import Counter

# === Constants ===
ALPHABET = string.ascii_lowercase
ENGLISH_FREQ = {
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 13.0, 'f': 2.2, 'g': 2.0,
    'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7,
    'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8,
    'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074
}


# === Caesar Cipher ===
def caesar_encrypt(text, shift):
    """Encrypt text using Caesar cipher with given shift."""
    return ''.join(
        ALPHABET[(ALPHABET.index(c) + shift) % 26] if c in ALPHABET else c
        for c in text.lower()
    )

def caesar_decrypt(text, shift):
    """Decrypt Caesar cipher text with given shift."""
    return caesar_encrypt(text, -shift)

def caesar_crack(ciphertext):
    """Crack Caesar cipher without knowing the key using frequency analysis."""
    scored = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = frequency_score(decrypted)
        scored.append((score, shift, decrypted))
    return max(scored, key=lambda x: x[0])[1:]


# === Atbash Cipher ===
def atbash_cipher(text):
    """Encrypt or decrypt using Atbash cipher (symmetric)."""
    return ''.join(
        ALPHABET[25 - ALPHABET.index(c)] if c in ALPHABET else c
        for c in text.lower()
    )


# === Vigenère Cipher ===
def vigenere_encrypt(text, key):
    """Encrypt text using Vigenère cipher with key."""
    key = key.lower()
    return ''.join(
        ALPHABET[(ALPHABET.index(c) + ALPHABET.index(key[i % len(key)])) % 26] if c in ALPHABET else c
        for i, c in enumerate(text.lower())
    )

def vigenere_decrypt(ciphertext, key):
    """Decrypt Vigenère cipher text using key."""
    key = key.lower()
    return ''.join(
        ALPHABET[(ALPHABET.index(c) - ALPHABET.index(key[i % len(key)])) % 26] if c in ALPHABET else c
        for i, c in enumerate(ciphertext.lower())
    )


# === Frequency Analysis ===
def frequency_score(text):
    """Score how close the letter frequency of text matches English."""
    filtered = [c for c in text if c in ALPHABET]
    if not filtered:
        return float('-inf')
    counts = Counter(filtered)
    total = len(filtered)
    return -sum(abs(100 * counts.get(c, 0) / total - ENGLISH_FREQ[c]) for c in ALPHABET)

def guess_caesar_shift(column):
    """Guess Caesar shift for a column based on English frequency match."""
    scores = []
    for shift in range(26):
        decrypted = ''.join(ALPHABET[(ALPHABET.index(c) - shift) % 26] for c in column)
        scores.append((frequency_score(decrypted), shift))
    return max(scores)[1]

def predict_vigenere_key(ciphertext, max_key_len=12):
    """Predict Vigenère key using frequency analysis (no key needed)."""
    text = ''.join(c for c in ciphertext if c in ALPHABET)
    best_key = ""
    best_score = float('-inf')

    for key_len in range(1, max_key_len + 1):
        candidate_key = ''.join(
            ALPHABET[guess_caesar_shift(text[i::key_len])]
            for i in range(key_len)
        )
        decrypted = vigenere_decrypt(text, candidate_key)
        score = frequency_score(decrypted)
        if score > best_score:
            best_key = candidate_key
            best_score = score

    return best_key


# === CLI ===
def run_cli():
    print("\n🔐 Welcome to the Advanced Cryptology Toolkit\n")
    menu = """
1. Vigenère Encrypt
2. Vigenère Decrypt (known key)
3. Vigenère Decrypt (predict key)
4. Caesar Encrypt
5. Caesar Decrypt (known shift)
6. Caesar Crack (no key)
7. Atbash Cipher
8. Exit
"""
    while True:
        print(menu)
        choice = input("Enter option (1-8): ").strip()

        if choice == '1':
            msg = input("Message to encrypt: ")
            key = input("Vigenère key: ")
            print("Encrypted:", vigenere_encrypt(msg, key))

        elif choice == '2':
            msg = input("Encrypted message: ")
            key = input("Key: ")
            print("Decrypted:", vigenere_decrypt(msg, key))

        elif choice == '3':
            msg = input("Encrypted message: ")
            key = predict_vigenere_key(msg)
            print("Predicted key:", key)
            print("Decrypted:", vigenere_decrypt(msg, key))

        elif choice == '4':
            msg = input("Message to encrypt: ")
            shift = int(input("Caesar shift (0-25): "))
            print("Encrypted:", caesar_encrypt(msg, shift))

        elif choice == '5':
            msg = input("Message to decrypt: ")
            shift = int(input("Caesar shift (0-25): "))
            print("Decrypted:", caesar_decrypt(msg, shift))

        elif choice == '6':
            msg = input("Encrypted message: ")
            shift, plain = caesar_crack(msg)
            print(f"Predicted shift: {shift}")
            print("Decrypted:", plain)

        elif choice == '7':
            msg = input("Message for Atbash cipher: ")
            print("Result:", atbash_cipher(msg))

        elif choice == '8':
            print("👋 Exiting. Stay secure!")
            break

        else:
            print("Invalid choice. Try again.")

# === Entry Point ===
if __name__ == '__main__':
    run_cli()
