from ciphermoji import CipherMoji

# Initialize CipherMoji
ciphermoji = CipherMoji("MY SUPER SECRET PASSPHRASE")

# Encrypt a message
encrypted = ciphermoji.encrypt("Hello World!")
print(encrypted)

# Decrypt the message
decrypted = ciphermoji.decrypt(encrypted)
print(decrypted)
