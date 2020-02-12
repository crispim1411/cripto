Encriptação AES
================

Código para encriptação simétrica utilizado Advanced Encryption Standard(AES). Para o processo de encriptação foram utilizados os seguintes modos:

* CBC: Cipher Block Chaining
* PKCS5Padding: Public Key Cryptography Standards
* PBKDF2WithHmacSHA256:
	* PBKDF2: Password-Based Key Derivation Function 2
	* Hmac: Hash-based Message Authentication Code
	* SHA256: hash de 256 bits

Exemplo de utilização
----------------------
::

    from aes import AESCipher

    plaintext = "Teste criptografia AES-CBC em Python"
    password = "senhaexemplo123"

    cipher = AESCipher(password)

    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)

    print(f"texto: {plaintext}")
    print(f"texto cifrado: {ciphertext}")
    print(f"texto decifrado: {decrypted}")