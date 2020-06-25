from base64 import b64encode, b64decode
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

PBKDF2_ITERATIONS = 32767
SALT_SIZE = 16

def encrypt(message, password):
    salt = get_random_bytes(SALT_SIZE)
    private_key = pbkdf2_hmac('SHA256', password.encode(), salt, PBKDF2_ITERATIONS)

    cipher = AES.new(private_key, AES.MODE_CBC)
    cipher_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    ciphertext = b64encode(salt + cipher.iv + cipher_bytes).decode('utf-8')
    return ciphertext

def decrypt(encrypted, password):
    ciphertext = b64decode(encrypted)
    if len(ciphertext) < 48:
        return "Erro: Dados incompletos para decifrar"

    salt = ciphertext[:SALT_SIZE]
    iv = ciphertext[SALT_SIZE:SALT_SIZE+16]
    content = ciphertext[SALT_SIZE+16:]

    private_key = pbkdf2_hmac('SHA256', password.encode(), salt, PBKDF2_ITERATIONS)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    text_bytes = unpad(cipher.decrypt(content), AES.block_size)
    plaintext = text_bytes.decode('utf-8')
    return plaintext
