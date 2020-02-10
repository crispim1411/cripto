import base64
import hashlib
import os
#from Crypto import Random
from Crypto.Cipher import AES

block_size = 16
pad = lambda s: s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)
unpad = lambda s: s[0:-ord(s[-1:])]
#iv = os.urandom(AES.block_size)  # Random IV
#iv = "iv testando aaaa".encode()


def get_private_key(secret_key, salt):
    return hashlib.pbkdf2_hmac('SHA256', secret_key.encode(), salt.encode(), 65536, 32)


def encrypt(message, secret_key, salt):
    private_key = get_private_key(secret_key, salt)
    message = pad(message)
    iv = "iv testando aaaa".encode()
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    cipher_bytes = base64.b64encode(iv + cipher.encrypt(message))
    return bytes.decode(cipher_bytes)


def decrypt(encoded, secret_key, salt):
    private_key = get_private_key(secret_key, salt)
    cipher_text = base64.b64decode(encoded)
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    plain_bytes = unpad(cipher.decrypt(cipher_text[block_size:]));
    return bytes.decode(plain_bytes)


def read_content():
    with open('encrypted_java') as f:
        ciphertext = ""
        for line in f.readlines():
            ciphertext += line

    return ciphertext


def save_content(ciphertext):
    with open('encrypted_python', 'w') as f:
        f.write(ciphertext)


plain_text = "Mensagem criptografada no Python"
secret_key = "yourSecretKey"
salt = "anySaltYouCanUseOfOn"

os.chdir("../AES_python_java/AES_python_java")

# Python -> Java
cipher_python = encrypt(plain_text, secret_key, salt)
save_content(cipher_python)
decrypted_python = decrypt(cipher_python, secret_key, salt)
print(f"Cipher by Python: {cipher_python}")
print(f"Decrypted: {decrypted_python}\n")

# Java -> Python
cipher_java = read_content()
decrypted_java = decrypt(cipher_java, secret_key, salt)
print(f"Cipher by Java: {cipher_java}")
print(f"Decrypted: {decrypted_java}")



