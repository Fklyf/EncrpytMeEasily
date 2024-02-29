import os
import socket
import platform
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken

def clear_screen():
    """Clears the console screen based on the operating system."""
    if platform.system() == "Windows":
        os.system('cls')
    else:  # Linux and Mac
        os.system('clear')

def generate_encryption_key(seed_numbers):
    """Generates a Fernet encryption key based on the provided seed numbers."""
    # Convert the seed numbers into a consistent string
    seed_string = ''.join(map(str, seed_numbers))
    # Use the seed string to generate a consistent hash
    hasher = hashlib.sha256()
    hasher.update(seed_string.encode())
    # Fernet key must be 32 bytes long, so we use the first 32 bytes of the hash
    key = base64.urlsafe_b64encode(hasher.digest())
    return key

def server_program():
    clear_screen()
    # Modified to provide a default set of numbers if Enter is pressed without input
    seed_input = input("Enter the 6 numbers separated by space for the encryption key (press Enter for default): ").strip()
    if seed_input == "":
        seed_numbers = [1, 2, 3, 4, 5, 6]  # Default seed numbers
    else:
        seed_numbers = list(map(int, seed_input.split()))
    
    if len(seed_numbers) != 6:
        print("Invalid number of seed numbers. Exiting.")
        return

    encryption_key = generate_encryption_key(seed_numbers)
    cipher_suite = Fernet(encryption_key)
    # The rest of your server_program function follows as before...

    while True:
        clear_screen()
        
        ip_address = input("Enter the IP address to bind to (press Enter for all interfaces): ").strip()
        if not ip_address:
            ip_address = '0.0.0.0'

        server_socket = socket.socket()
        try:
            server_socket.bind((ip_address, 5000))
            print(f"Server is waiting for connections on {ip_address}:5000...")
            break  # Exit the loop on successful bind
        except Exception as e:
            print(f"Failed to bind to {ip_address}:5000: {e}")
            print("Please try again with a different IP address or check your network configuration.")
            server_socket.close()
            input("Press Enter to continue...")  # Wait for user input before retrying

    server_socket.listen(2)
    print("Server is waiting for connections...")

    while True:
        conn, address = server_socket.accept()
        print(f"Connection established with a client from port: {address[1]}")

        try:
            encrypted_username = conn.recv(1024)
            if not encrypted_username:
                print("No username received. Closing connection.")
                conn.close()
                continue
            username = cipher_suite.decrypt(encrypted_username).decode()
            print(f"Username received: {username}")
        except InvalidToken as e:
            print(f"Decryption failed for username: {e}")
            conn.close()
            continue
        except Exception as e:
            print(f"Error processing username: {e}")
            conn.close()
            continue

        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    print("No data received. Closing connection.")
                    break

                decrypted_message = cipher_suite.decrypt(data).decode()
                print(f"From {username}: " + decrypted_message)

                # Modified to include the sender's username in the response
                response_message = f"{username}: {decrypted_message}".encode()
                encrypted_message = cipher_suite.encrypt(response_message)
                conn.send(encrypted_message)
            except InvalidToken as e:
                print(f"Decryption failed: {e}")
                break
            except Exception as e:
                print(f"Error during message handling: {e}")
                break

        conn.close()
        print(f"Connection with {username} closed.")

if __name__ == '__main__':
    server_program()
