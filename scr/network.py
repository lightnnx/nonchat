import socket
import threading
from .encryption import rsa_encrypt, rsa_decrypt, aes_encrypt, aes_decrypt, sign_message, verify_signature

class Peer:
    def __init__(self, host, port, private_key, public_key):
        self.host = host
        self.port = port
        self.private_key = private_key
        self.public_key = public_key
        self.peers = {}
        self.pending_requests = []
        self.session_keys = {}  # Словарь для хранения симметричных ключей для каждого пира

    def start(self):
        server_thread = threading.Thread(target=self.server)
        server_thread.start()

    def server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"Сервер запущен на {self.host}:{self.port}")
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(conn,)).start()

    def handle_client(self, conn):
        while True:
            data = conn.recv(4096)
            if not data:
                break
            message = data.decode()
            if message.startswith("REQUEST:"):
                username, public_key = message.split(":")[1], message.split(":")[2]
                self.pending_requests.append((username, public_key))
                print(f"Запрос на чат от {username}")
            elif message.startswith("SESSION_KEY:"):
                username = message.split(":")[1]
                encrypted_session_key = message.split(":")[2].encode()
                session_key = rsa_decrypt(self.private_key, encrypted_session_key)
                self.session_keys[username] = session_key
                print(f"Симметричный ключ для {username} получен")
            elif message.startswith("MESSAGE:"):
                username = message.split(":")[1]
                nonce, ciphertext, tag, signed_message = message.split(":")[2:]
                decrypted_message = self.receive_message(username, nonce, ciphertext, tag, signed_message)
                print(f"Получено сообщение от {username}: {decrypted_message}")
            else:
                print(f"Получено: {message}")

    def send_request(self, target_host, target_port, username):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_host, target_port))
        request_message = f"REQUEST:{username}:{self.public_key.decode()}"
        client_socket.send(request_message.encode())
        client_socket.close()

    def send_session_key(self, target_host, target_port, username, target_public_key, session_key):
        encrypted_session_key = rsa_encrypt(target_public_key.encode(), session_key)
        session_key_message = f"SESSION_KEY:{username}:{encrypted_session_key.decode()}"
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_host, target_port))
        client_socket.send(session_key_message.encode())
        client_socket.close()

    def send_message(self, target_host, target_port, username, message):
        session_key = self.session_keys[username]
        nonce, ciphertext, tag = aes_encrypt(session_key, message.encode())
        signed_message = sign_message(self.private_key, ciphertext)
        message_packet = f"MESSAGE:{username}:{nonce.decode()}:{ciphertext.decode()}:{tag.decode()}:{signed_message.decode()}"
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_host, target_port))
        client_socket.send(message_packet.encode())
        client_socket.close()

    def receive_message(self, username, nonce, ciphertext, tag, signed_message):
        session_key = self.session_keys[username]
        if verify_signature(self.peers[username]['public_key'], ciphertext.encode(), signed_message.encode()):
            decrypted_message = aes_decrypt(session_key, nonce.encode(), ciphertext.encode(), tag.encode())
            return decrypted_message.decode()
        else:
            print("Ошибка проверки подписи.")
            return None
