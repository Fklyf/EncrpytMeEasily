import socket
from cryptography.fernet import Fernet, InvalidToken

def server_program():
    server_socket = socket.socket()
    server_socket.bind(('0.0.0.0', 5000))  # Listen on all network interfaces
    print("Server is waiting for connections...")
    server_socket.listen(2)

    while True:
        conn, address = server_socket.accept()
        # Anonymize the client's IP address in the output
        print(f"Connection established with a client from port: {address[1]}")

        try:
            key = conn.recv(1024)
            if not key:
                print("Failed to receive encryption key. Closing connection.")
                conn.close()
                continue
            cipher_suite = Fernet(key)
            print("Encryption key received successfully.")
        except Exception as e:
            print(f"Error setting up encryption: {e}")
            conn.close()
            continue

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

                response_message = f"Echo: {decrypted_message}".encode()
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
