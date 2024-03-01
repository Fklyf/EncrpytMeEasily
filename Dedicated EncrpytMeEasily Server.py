import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.clock import mainthread
import socket
import threading
import hashlib
import base64
from cryptography.fernet import Fernet

kivy.require('2.0.0')

class ServerApp(App):
    def build(self):
        self.server = ServerBackend(app=self)
        layout = BoxLayout(orientation='vertical')

        self.info_log = Label(size_hint_y=0.8, markup=True)
        layout.add_widget(self.info_log)

        self.passkey_input = TextInput(size_hint_y=0.1, multiline=False, hint_text='Enter 6-digit passkey and press Enter')
        self.passkey_input.bind(on_text_validate=self.on_passkey_enter)
        layout.add_widget(self.passkey_input)

        control_layout = BoxLayout(size_hint_y=0.1)
        start_button = Button(text='Start Server')
        start_button.bind(on_press=self.start_server)
        control_layout.add_widget(start_button)

        stop_button = Button(text='Stop Server')
        stop_button.bind(on_press=self.stop_server)
        control_layout.add_widget(stop_button)

        layout.add_widget(control_layout)

        return layout

    @mainthread
    def update_info_log(self, message):
        self.info_log.text += f"\n{message}"

    def on_passkey_enter(self, instance):
        passkey = self.passkey_input.text
        if len(passkey) == 6 and passkey.isdigit():
            self.server.generate_encryption_key([int(digit) for digit in passkey])
            self.update_info_log('Passkey set. You can start the server now.')
        else:
            self.update_info_log('Invalid passkey. Please enter a 6-digit number.')
        self.passkey_input.text = ''

    def start_server(self, instance):
        self.server.start_server()

    def stop_server(self, instance):
        self.server.stop_server()

class ServerBackend:
    def __init__(self, app):
        self.app = app
        self.server_socket = None
        self.is_active = False
        self.clients = []  # Keep track of client sockets
        self.encryption_key = None
        self.cipher_suite = None

    def generate_encryption_key(self, seed_numbers):
        seed_string = ''.join(map(str, seed_numbers))
        hasher = hashlib.sha256()
        hasher.update(seed_string.encode('utf-8'))
        key = base64.urlsafe_b64encode(hasher.digest()[:32])  # Ensure key is 32 bytes
        self.encryption_key = key
        self.cipher_suite = Fernet(key)
        self.app.update_info_log('Encryption key generated.')

    def start_server(self):
        if self.is_active:
            self.app.update_info_log("Server is already running.")
            return
        if not self.encryption_key:
            self.app.update_info_log("Please set the passkey before starting the server.")
            return

        self.is_active = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', 5000))
        self.server_socket.listen(5)
        self.app.update_info_log("Server started... Listening for connections...")
        threading.Thread(target=self.accept_connections).start()

    def accept_connections(self):
        while self.is_active:
            try:
                client_socket, address = self.server_socket.accept()
                self.app.update_info_log(f"Connection established with {address}")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                client_thread.start()
                self.clients.append(client_socket)
            except Exception as e:
                self.app.update_info_log(f"Server stopped listening: {e}")
                self.is_active = False

    def broadcast(self, message):
        for client in self.clients:
            try:
                client.send(message)
            except Exception as e:
                self.app.update_info_log(f"Broadcast error to {client.getpeername()}: {e}")
                self.clients.remove(client)

    def handle_client(self, client_socket, address):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                # Assuming `self.cipher_suite` is already set up with the encryption key
                decrypted_data = self.cipher_suite.decrypt(data).decode('utf-8')
                self.app.update_info_log(f"Message from {address}: {decrypted_data}")
                # Encrypt the message again for broadcasting
                broadcast_encrypted = self.cipher_suite.encrypt(decrypted_data.encode('utf-8'))
                self.broadcast(broadcast_encrypted)
        except Exception as e:
            self.app.update_info_log(f"Error with client {address}: {e}")
        finally:
            client_socket.close()
            self.clients.remove(client_socket)
            self.app.update_info_log(f"Connection with {address} closed.")

    def stop_server(self):
        if self.is_active:
            self.is_active = False
            for client in self.clients:
                client.close()
            self.server_socket.close()
            self.app.update_info_log("Server stopped.")

if __name__ == '__main__':
    ServerApp().run()
