from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

KEY_SIZE = 2048
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12

# Генерация ключей
def generate_rsa_keys():
    key = RSA.generate(KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Шифрование RSA
def rsa_encrypt(public_key, message):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(message)

# Расшифровка RSA
def rsa_decrypt(private_key, encrypted_message):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_message)

# Подпись сообщения
def sign_message(private_key, message):
    private_key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

# Проверка подписи
def verify_signature(public_key, message, signature):
    public_key = RSA.import_key(public_key)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Шифрование AES
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(AES_NONCE_SIZE))
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

# Расшифровка AES
def aes_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
