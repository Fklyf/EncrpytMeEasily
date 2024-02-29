import socket
import base64
import hashlib
import os
import platform
from cryptography.fernet import Fernet

def clear_screen():
    """Clears the console based on the operating system."""
    command = 'cls' if platform.system() == 'Windows' else 'clear'
    os.system(command)

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
    clear_screen()  # Clear the screen at the start
    host = input("Enter the server's IP address (press Enter for default localhost): ")
    if not host.strip():
        host = '127.0.0.1'  # Default to localhost if no input
    port = 5000

    clear_screen()  # Clear the screen before asking for seed input

    seed_numbers = get_seed_input()
    encryption_key = generate_encryption_key(seed_numbers)
    cipher_suite = Fernet(encryption_key)

    clear_screen()  # Clear the screen before asking for username

    username = input("Enter your username: ")
    
    with socket.socket() as client_socket:
        client_socket.connect((host, port))
        encrypted_username = cipher_suite.encrypt(username.encode())
        client_socket.send(encrypted_username)
        print(f"Connected to the server as {username}.")

        try:
            while True:
                message = input(": ")
                if message.lower() == 'bye':
                    break
                encrypted_message = cipher_suite.encrypt(message.encode())
                client_socket.send(encrypted_message)

                response = cipher_suite.decrypt(client_socket.recv(1024)).decode()
                # Check if the message is from the user itself and skip displaying it
                if not response.startswith(username + ":"):
                    print(response)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("Connection closed.")

if __name__ == '__main__':
    client_program()
