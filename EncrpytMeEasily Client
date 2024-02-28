import socket
from cryptography.fernet import Fernet

def client_program():
    client_socket = socket.socket()
    host = input("Enter server IP or press Enter for local: ").strip() or socket.gethostname()
    port = 5000
    try:
        client_socket.connect((host, port))
        print("Connected to the server.")
    except Exception as e:
        print(f"Failed to connect to the server: {e}")
        return

    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    client_socket.send(key)
    print("Encryption key sent to the server.")

    username = input("Enter your username: ")
    encrypted_username = cipher_suite.encrypt(username.encode())
    client_socket.send(encrypted_username)
    print("Username sent to the server.")

    while True:
        message = input(" -> ")
        if message.lower() == 'bye':
            break

        encrypted_message = cipher_suite.encrypt(message.encode())
        client_socket.send(encrypted_message)

        response = client_socket.recv(1024)
        decrypted_response = cipher_suite.decrypt(response).decode()
        print('Server says: ' + decrypted_response)

    client_socket.close()
    print("Disconnected from the server.")

if __name__ == '__main__':
    client_program()
