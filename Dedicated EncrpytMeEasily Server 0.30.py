import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.effects.scroll import ScrollEffect
from kivy.factory import Factory
from kivy.clock import Clock, mainthread
from kivy.graphics import Color, Rectangle
from kivy.core.window import Window
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import socket
import threading
import hashlib
import base64
from cryptography.fernet import Fernet
import sys

# Constants for shared layout
HEADER_HEIGHT = 50
CONTENT_PADDING = [10]
BAR_WIDTH = 10
WINDOW_BACKGROUND_COLOR = (0.3, 0.3, 0.3, 1)
LABEL_PADDING = 10
TEXT_INPUT_HEIGHT = 50
TEXT_INPUT_WIDTH = 99


# Shared layout function
def build_shared_layout(app, title_text, input_hint, button_callback):
    layout = BoxLayout(orientation='vertical')

    # Header layout
    header_layout = BoxLayout(size_hint_y=None, height=HEADER_HEIGHT)
    title_label = Label(text=title_text, size_hint_x=0.95)
    close_button = Button(text='X', size_hint_x=None, width=50)
    close_button.bind(on_press=lambda x: app.stop())
    header_layout.add_widget(title_label)
    header_layout.add_widget(close_button)
    layout.add_widget(header_layout)

    # Command input layout
    command_input_layout = BoxLayout(size_hint_y=None, height=TEXT_INPUT_HEIGHT, padding=CONTENT_PADDING)
    app.update_background = lambda *args: command_input_layout.canvas.before.clear()

    with command_input_layout.canvas.before:
        Color(rgba=WINDOW_BACKGROUND_COLOR)
        Rectangle(size=(Window.width, TEXT_INPUT_HEIGHT), pos=command_input_layout.pos)

    Window.bind(on_resize=app.handle_window_resize)

    # Content layout for log
    content_layout = BoxLayout(padding=CONTENT_PADDING, size_hint_y=None)
    app.info_log = Label(size_hint_y=None, markup=True, halign="left", valign="bottom")
    app.info_log.bind(
        width=lambda *x: app.info_log.setter('text_size')(app.info_log, (app.info_log.width, None)),
        texture_size=lambda *x: app.update_content_layout_height(app.info_log.texture_size[1]))
    content_layout.add_widget(app.info_log)

    # ScrollView for logs
    log_scroll_view = CustomScrollView(size_hint=(1, 1), do_scroll_x=False)
    log_scroll_view.add_widget(content_layout)
    layout.add_widget(log_scroll_view)

    # Command input layout with reset button
    app.passkey_input = TextInput(multiline=False, hint_text=input_hint)
    app.passkey_input.bind(on_text_validate=button_callback)

    reset_button = Button(text='New ID', size_hint_x=None, height=TEXT_INPUT_HEIGHT, width=TEXT_INPUT_WIDTH)
    reset_button.bind(on_press=app.restart_process)
    command_input_layout.add_widget(app.passkey_input)
    command_input_layout.add_widget(reset_button)

    layout.add_widget(command_input_layout)

    return layout


# Custom Scroll Effect to remove scrolling momentum
class NoMomentumScrollEffect(ScrollEffect):
    def update_velocity(self, dt):
        self.velocity = 0


Factory.register('NoMomentumScrollEffect', cls=NoMomentumScrollEffect)


class CustomScrollView(ScrollView):
    def __init__(self, **kwargs):
        super(CustomScrollView, self).__init__(**kwargs)
        self.effect_cls = 'NoMomentumScrollEffect'
        self.scroll_type = ['bars', 'content']
        self.bar_width = 0
        Clock.schedule_once(self.check_content_size)
        self.bind(size=self.check_content_size)

    def check_content_size(self, *args):
        if self.children:
            content = self.children[0]
            if content.height > self.height:
                self.do_scroll_y = True
                self.bar_width = BAR_WIDTH  # Show scrollbar
            else:
                self.do_scroll_y = False
                self.bar_width = 0  # Hide scrollbar


class ServerApp(App):
    def build(self):
        self.server = ServerBackend(app=self)
        return build_shared_layout(self, 'EncryptMeEasily Server 0.30',
                                   'Enter passkey (4-16 digits) or press Enter for default.', self.on_passkey_enter)

    def on_passkey_enter(self, instance):
        passkey = self.passkey_input.text.strip()
        if not passkey:
            # Use default passkey
            passkey = '1234567812345678'
        # Set the passkey
        self.server.generate_encryption_key(passkey)
        self.info_log.text += f"\nPasskey set. Enter IP or press Enter for default IP."
        self.passkey_input.hint_text = 'Press Enter for default IP (0.0.0.0) or enter IP'
        self.passkey_input.text = ''  # Clear input field after passkey entry
        self.passkey_input.bind(on_text_validate=self.on_ip_enter)

    def on_ip_enter(self, instance):
        ip_address = self.passkey_input.text.strip()
        if not ip_address:
            # If no IP is entered, bind to default 0.0.0.0
            ip_address = '0.0.0.0'
        port = 5000  # Default port
        self.server.start_server(ip_address, port)
        self.info_log.text += f"\nAttempting to bind server to {ip_address}:{port}."
        self.passkey_input.text = ''  # Clear input field after IP entry

    def handle_window_resize(self, instance, width, height):
        self.update_background()

    def update_content_layout_height(self, height):
        self.info_log.height = height
        self.info_log.size_hint_y = None
        content_layout = self.info_log.parent
        if content_layout:
            content_layout.height = height + LABEL_PADDING

    @mainthread
    def update_info_log(self, message):
        self.info_log.text += f"\n{message}"

    def restart_process(self, instance):
        self.info_log.text = "Welcome to EncryptMeEasily"
        self.passkey_input.text = ''
        self.passkey_input.hint_text = 'Enter passkey.'

    def on_stop(self):
        # Handle KeyboardInterrupt (CTRL+C) properly
        try:
            if self.server.is_active:
                self.server.stop_server()
        except Exception as e:
            self.update_info_log(f"Error during shutdown: {e}")
        sys.exit(0)  # Ensure clean exit


class ServerBackend:
    def __init__(self, app):
        self.app = app
        self.server_socket = None
        self.is_active = False
        self.clients = []
        self.encryption_key = None
        self.cipher_suite = None

    def generate_encryption_key(self, passkey):  # Accept passkey as a parameter
        hasher = hashlib.sha256()
        hasher.update(passkey.encode('utf-8'))  # Use passkey to derive the encryption key
        key = base64.urlsafe_b64encode(hasher.digest()[:32])
        self.encryption_key = key
        self.cipher_suite = Fernet(key)
        self.app.update_info_log('Encryption key generated.')


    def start_server(self, ip_address, port):
        if self.is_active:
            self.app.update_info_log("Server is already running.")
            return
        if not self.encryption_key:
            self.app.update_info_log("Please set the passkey before starting the server.")
            return

        try:
            self.is_active = True
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((ip_address, port))
            self.server_socket.listen(5)
            self.app.update_info_log(f"Server started on {ip_address}:{port}. Listening for connections...")
            threading.Thread(target=self.accept_connections, daemon=True).start()
        except Exception as e:
            self.app.update_info_log(f"Failed to start server: {e}")

    def accept_connections(self):
        while self.is_active:
            try:
                client_socket, address = self.server_socket.accept()
                self.app.update_info_log(f"Connection established with {address}")
                threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()
            except Exception as e:
                self.app.update_info_log(f"Error accepting connections: {e}")
                break

    def handle_client(self, client_socket, address):
        try:
            encrypted_username = client_socket.recv(1024)
            if encrypted_username:
                username = self.cipher_suite.decrypt(encrypted_username).decode('utf-8')
                self.app.update_info_log(f"{username} connected from {address}")
            else:
                raise Exception("Failed to receive username.")

            while True:
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message:
                    break
                message = self.cipher_suite.decrypt(encrypted_message).decode('utf-8')
                self.app.update_info_log(f"{username}: {message}")
                self.broadcast(f"{username}: {message}", sender_socket=client_socket)
        except Exception as e:
            self.app.update_info_log(f"Error with client {address}: {e}")
        finally:
            client_socket.close()
            self.app.update_info_log(f"{address} has disconnected.")

    def broadcast(self, message, sender_socket=None):
        encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8'))
        for client_socket in self.clients:
            if client_socket is not sender_socket:
                client_socket.send(encrypted_message)

    def stop_server(self):
        if self.is_active:
            self.app.update_info_log("Stopping the server...")
            self.is_active = False
            try:
                self.server_socket.close()
            except Exception as e:
                self.app.update_info_log(f"Error closing server socket: {e}")


if __name__ == '__main__':
    try:
        ServerApp().run()
    except KeyboardInterrupt:
        print("Server is shutting down...")
        sys.exit(0)
