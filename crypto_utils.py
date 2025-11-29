from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(file_path + ".enc", 'wb') as f_enc:
        f_enc.write(cipher.nonce)
        f_enc.write(tag)
        f_enc.write(ciphertext)

def decrypt_file(enc_file_path, key):
    with open(enc_file_path, 'rb') as f_enc:
        nonce = f_enc.read(16)
        tag = f_enc.read(16)
        ciphertext = f_enc.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data
