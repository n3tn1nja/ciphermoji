import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

EMOJI_SET = list("🤡😈")


class CipherMoji:
    def __init__(self, passphrase, salt="Caesar"):
        """Initializes CipherMoji with a passphrase/salt and sets up the emoji mapping."""

        self.passphrase = passphrase.encode()
        self.characters = "".join(EMOJI_SET)
        self.base = len(self.characters)
        self.salt = salt.encode()
        self.char_to_index = {char: idx for idx, char in enumerate(self.characters)}
        self.key = self.generate_key()
        self.cipher = Fernet(self.key)

    def generate_key(self):
        """Generates a Fernet key from a passphrase using PBKDF2."""

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend(),
        )

        return base64.urlsafe_b64encode(kdf.derive(self.passphrase))

    def encrypt(self, data):
        """Encrypts the input data and encodes it using the custom character set"""

        encrypted = self.cipher.encrypt(data.encode())
        x = int.from_bytes(encrypted, "big")
        result = []
        while x > 0:
            x, remainder = divmod(x, self.base)
            result.append(self.characters[remainder])
        return "".join(reversed(result))

    def decrypt(self, data):
        """Decodes the input data and decrypts it."""

        x = 0
        for char in data:
            x = x * self.base + self.char_to_index[char]
        decrypted = self.cipher.decrypt(x.to_bytes((x.bit_length() + 7) // 8, "big"))
        return decrypted.decode()
