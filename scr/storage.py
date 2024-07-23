import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

DATA_DIR = 'data/'

def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def save_message(chat_id, message, password):
    ensure_data_dir()
    key = SHA256.new(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    with open(os.path.join(DATA_DIR, chat_id), 'ab') as f:
        f.write(cipher.iv + ct_bytes)

def load_messages(chat_id, password):
    key = SHA256.new(password.encode()).digest()
    messages = []
    try:
        with open(os.path.join(DATA_DIR, chat_id), 'rb') as f:
            while True:
                iv = f.read(16)
                if not iv:
                    break
                ct = f.read(AES.block_size)
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                pt = unpad(cipher.decrypt(ct), AES.block_size)
                messages.append(pt.decode())
    except FileNotFoundError:
        pass
    return messages
