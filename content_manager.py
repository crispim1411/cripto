def read_content(filename='encrypted_java'):
    with open(filename) as f:
        ciphertext = ""
        for line in f.readlines():
            ciphertext += line

    return ciphertext


def save_content(ciphertext, filename='encrypted_python'):
    with open(filename, 'w') as f:
        f.write(ciphertext)
