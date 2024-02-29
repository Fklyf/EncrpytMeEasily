import socket
import base64
import hashlib
from cryptography.fernet import Fernet

def generate_encryption_key(seed_numbers):
    """Generates a Fernet encryption key based on the provided seed numbers."""
    seed_string = ''.join(map(str, seed_numbers))
    hasher = hashlib.sha256()
    hasher.update(seed_string.encode())
    key = base64.urlsafe_b64encode(hasher.digest())
    return key

def get_seed_input():
    """Prompts the user for seed numbers or uses a default set."""
    seed_input = input("Enter the 6 numbers separated by space for the encryption key (press Enter for default): ")
    if seed_input.strip() == "":
        return [1, 2, 3, 4, 5, 6]  # Default seed
    else:
        return list(map(int, seed_input.split()))

def client_program():
    # Prompt for the server's IP address
    host = input("Enter the server's IP address: ")
    port = 5000  # Assuming the port is fixed for simplicity

    seed_numbers = get_seed_input()
    encryption_key = generate_encryption_key(seed_numbers)
    cipher_suite = Fernet(encryption_key)

    client_socket = socket.socket()
    try:
        client_socket.connect((host, port))
        print("Connected to the server.")

        username = input("Enter your username: ")  # Prompt user for username
        encrypted_username = cipher_suite.encrypt(username.encode())
        client_socket.send(encrypted_username)

        while True:
            message = input("Type your message (type 'bye' to exit): ")  # Message input
            if message.lower() == 'bye':  # Exit command
                break
            encrypted_message = cipher_suite.encrypt(message.encode())
            client_socket.send(encrypted_message)

            # Receive and decrypt the server's response
            response = client_socket.recv(1024)
            decrypted_response = cipher_suite.decrypt(response).decode()
            print(decrypted_response)  # Display decrypted response

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

if __name__ == '__main__':
    client_program()
