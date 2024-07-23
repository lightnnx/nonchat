import os
from .storage import load_messages, save_message
from .network import Peer
from .encryption import generate_rsa_keys

private_key, public_key = generate_rsa_keys()
peer = Peer('0.0.0.0', 5000, private_key, public_key)
peer.start()

def show_main_screen():
    while True:
        print("1. Показать чаты")
        print("2. Создать новый чат")
        print("3. Подтвердить запросы")
        print("4. Выйти")
        choice = input("Выберите действие: ")
        if choice == '1':
            show_chats()
        elif choice == '2':
            create_chat()
        elif choice == '3':
            confirm_requests()
        elif choice == '4':
            break
        else:
            print("Неверный выбор.")

def show_chats():
    chats = os.listdir("data/")
    for chat in chats:
        print(chat)
    chat_id = input("Введите ID чата для открытия: ")
    password = input("Введите пароль для расшифровки: ")
    messages = load_messages(chat_id, password)
    for msg in messages:
        print(msg)
    while True:
        msg = input("Введите сообщение (или 'exit' для выхода): ")
        if msg == 'exit':
            break
        save_message(chat_id, msg, password)

def create_chat():
    username = input("Введите никнейм собеседника: ")
    target_host = input("Введите IP собеседника: ")
    target_port = int(input("Введите порт собеседника: "))
    peer.send_request(target_host, target_port, username)
    print(f"Запрос на чат с {username} отправлен. Ожидайте подтверждения.")

def confirm_requests():
    for request in peer.pending_requests:
        print(f"Запрос от {request[0]}")
    username = input("Введите никнейм для подтверждения: ")
    for req in peer.pending_requests:
        if req[0] == username:
            peer.peers[username] = {'public_key': req[1]}
            session_key = os.urandom(AES_KEY_SIZE)
            peer.session_keys[username] = session_key
            peer.send_session_key(req[0], 5000, username, req[1], session_key)
            peer.pending_requests.remove(req)
            print(f"Чат с {username} подтверждён.")
            break

if __name__ == "__main__":
    show_main_screen()
