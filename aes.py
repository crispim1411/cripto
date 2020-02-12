import os
import base64
import hashlib
from Crypto.Cipher import AES

PBKDF2_ITERATIONS = 32767
SALT_SIZE = 16
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s.encode('UTF-8')) % BLOCK_SIZE) *\
                chr(BLOCK_SIZE - len(s.encode('UTF-8')) % BLOCK_SIZE)
unpad = lambda s: s[0:-ord(s[-1:])]


class AESCipher:
    def __init__(self, secret_key):
        self.key = secret_key

    def get_private_key(self, salt):
        return hashlib.pbkdf2_hmac('SHA256', self.key.encode(), salt, PBKDF2_ITERATIONS)

    def encrypt(self, message):
        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(AES.block_size)

        private_key = self.get_private_key(salt)
        message = pad(message)

        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        cipher_bytes = base64.b64encode(salt + iv + cipher.encrypt(message))
        return bytes.decode(cipher_bytes)

    def decrypt(self, encoded):
        ciphertext = base64.b64decode(encoded)

        if len(ciphertext) < 48:
            return "Erro: Dados incompletos para decifrar"

        salt = ciphertext[:SALT_SIZE]
        iv = ciphertext[SALT_SIZE:32]
        content = ciphertext[32:]

        private_key = self.get_private_key(salt)

        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        plain_bytes = unpad(cipher.decrypt(content))
        return bytes.decode(plain_bytes)





