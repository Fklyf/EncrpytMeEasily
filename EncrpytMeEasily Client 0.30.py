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


class ClientApp(App):
    def __init__(self, **kwargs):
        super(ClientApp, self).__init__(**kwargs)
        self.setup_stage = 'username'
        self.client_socket = None  # Initialize client socket as None
        self.username = ''
        self.server_address = '127.0.0.1'
        self.server_port = 5000
        self.encryption_key = None
        self.cipher_suite = None

    def build(self):
        # Ask for username first
        return build_shared_layout(self, 'EncryptMeEasily Client 0.30', 'Please enter a username.',
                                   self.on_message_enter)

    def on_message_enter(self, instance):
        text = instance.text.strip()

        if self.setup_stage == 'username':
            self.username = text
            self.setup_stage = 'connect'
            self.passkey_input.hint_text = 'Connecting to server...'
            self.connect_to_server()
            self.info_log.text += '\nUsername set. Connecting to server...'
            self.passkey_input.text = ''  # Clear text box

        elif self.setup_stage == 'connect':
            self.setup_stage = 'passkey'
            self.passkey_input.hint_text = 'Enter passkey or press Enter for default'
            self.info_log.text += '\nConnected to the server. Enter passkey or press Enter for default:'
            self.passkey_input.text = ''  # Clear text box

        elif self.setup_stage == 'passkey':
            self.encryption_key = self.generate_encryption_key(text if text else '1234567812345678')
            self.cipher_suite = Fernet(self.encryption_key)
            self.setup_stage = 'chat'
            self.passkey_input.hint_text = 'Enter message'
            self.send_username()
            self.info_log.text += '\nPasskey set. You can now enter messages.'
            self.passkey_input.text = ''  # Clear text box

        elif self.setup_stage == 'chat':
            self.send_message(text)
            self.passkey_input.text = ''  # Clear text box after sending message

    def connect_to_server(self):
        try:
            # Initialize and connect the socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_address, self.server_port))
            threading.Thread(target=self.listen_for_messages, daemon=True).start()
        except Exception as e:
            self.info_log.text += f'\nFailed to connect: {e}'

    def listen_for_messages(self):
        try:
            while True:
                encrypted_message = self.client_socket.recv(1024)
                if encrypted_message:
                    message = self.cipher_suite.decrypt(encrypted_message).decode('utf-8')
                    self.display_message(message)
                else:
                    break
        except Exception as e:
            self.display_message(f"Error: {e}")
            self.client_socket.close()

    @mainthread
    def display_message(self, message):
        self.info_log.text += f"\n{message}"

    def send_username(self):
        try:
            if self.client_socket:
                encrypted_username = self.cipher_suite.encrypt(self.username.encode('utf-8'))
                self.client_socket.send(encrypted_username)
        except Exception as e:
            self.info_log.text += f'\nFailed to send username: {e}'

    def send_message(self, message):
        try:
            if self.client_socket:
                encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8'))
                self.client_socket.send(encrypted_message)
                self.display_message(f"You: {message}")
            else:
                self.info_log.text += '\nNo active connection to send the message.'
        except Exception as e:
            self.info_log.text += f"\nFailed to send message: {e}"

    def restart_process(self, instance):
        self.info_log.text = "Welcome to EncryptMeEasily"
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception as e:
                self.info_log.text += f'\nError closing socket: {e}'
        self.client_socket = None
        self.setup_stage = 'username'
        self.passkey_input.text = ''  # Clear input field
        self.passkey_input.hint_text = 'Please enter a username.'

    def generate_encryption_key(self, passkey):
        hasher = hashlib.sha256()
        hasher.update(passkey.encode('utf-8'))
        return base64.urlsafe_b64encode(hasher.digest())

    def handle_window_resize(self, instance, width, height):
        self.update_background()

    def update_content_layout_height(self, height):
        self.info_log.height = height
        self.info_log.size_hint_y = None
        content_layout = self.info_log.parent
        if content_layout:
            content_layout.height = height + LABEL_PADDING


if __name__ == '__main__':
    try:
        ClientApp().run()
    except KeyboardInterrupt:
        print("Server is shutting down...")
        sys.exit(0)
