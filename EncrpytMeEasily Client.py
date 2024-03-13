import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.slider import Slider
from kivy.uix.button import Button
from kivy.uix.widget import Widget
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.effects.scroll import ScrollEffect
from kivy.factory import Factory
from kivy.properties import NumericProperty
from kivy.clock import Clock, mainthread
from kivy.graphics import Color, Rectangle, Line
from kivy.core.window import Window
from kivy.properties import ObjectProperty
import socket
import threading
import hashlib
import base64
from cryptography.fernet import Fernet
from kivy.animation import Animation
from kivy.metrics import dp
from kivy.config import Config
Config.set('kivy', 'keyboard_mode', 'systemanddock')

kivy.require('2.0.0')

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
        Clock.schedule_once(self.init_ui)
        self.bind(size=self.check_content_size)

    def check_content_size(self, *args):
        if self.children:
            content = self.children[0]
            # Enable scrolling and show scrollbar if content height exceeds view height
            if content.height > self.height:
                self.do_scroll_y = True
                self.bar_width = 10  # Show scrollbar by setting a non-zero width
            else:
                self.do_scroll_y = False
                self.bar_width = 0  # Hide scrollbar by setting width to 0

    def init_ui(self, dt):
        self.do_scroll_y = True  # Enable vertical scrolling
        with self.canvas.before:
            Color(rgba=(1, 1, 1, 1))  # Background color for the scrollbar area, adjust as needed
            self.border = Line(rectangle=(self.x + 1, self.y + 1, self.width - 2, self.height - 2), width=1.2)
        self.bind(pos=self.update_border, size=self.update_border)

    def update_border(self, *args):
        if hasattr(self, 'border'):
            self.border.rectangle = (self.x + 1, self.y + 1, self.width - 2, self.height - 2)

    def on_touch_down(self, touch):
        if touch.device == 'mouse' and touch.button in ('scrolldown', 'scrollup'):
            # Invert scrolling direction
            if touch.button == 'scrolldown':
                self.scroll_y = min(1, self.scroll_y + 0.1)  # Inverted to scroll up
            elif touch.button == 'scrollup':
                self.scroll_y = max(0, self.scroll_y - 0.1)  # Inverted to scroll down
            Animation(scroll_y=self.scroll_y, d=0.1, t='out_quad').start(self)
            return True
        return super(CustomScrollView, self).on_touch_down(touch)

    def on_touch_move(self, touch):
        if self.collide_point(*touch.pos):
            if not hasattr(self, 'last_touch_y') or touch.is_mouse_scrolling:
                self.last_touch_y = touch.y
            dy = touch.y - self.last_touch_y
            # Invert scroll direction by changing `- dy / self.height` to `+ dy / self.height`
            self.scroll_y = min(1, max(0, self.scroll_y + dy / self.height))
            self.last_touch_y = touch.y
            return True
        return super(CustomScrollView, self).on_touch_move(touch)

    def on_touch_up(self, touch):
        if self.collide_point(*touch.pos) and hasattr(self, 'last_touch_y'):
            del self.last_touch_y  # Remove the attribute when touch ends
        return super(CustomScrollView, self).on_touch_up(touch)

    def update_content_layout_height(self):
        content_layout = self.ids.content_layout  # Assuming you have given an id to your content layout in kv
        total_height = sum(child.height + content_layout.spacing for child in content_layout.children)
        content_layout.height = total_height
        content_layout.size_hint_y = None  # Allow manual height adjustment


class ClientApp(App):
    def __init__(self, **kwargs):
        super(ClientApp, self).__init__(**kwargs)
        self.setup_stage = 'username'  # First stage is to enter a username
        self.client_socket = None  # Initialize client_socket

    def build(self):
        self.server_address = '127.0.0.1'
        self.server_port = 5000
        self.encryption_key = self.generate_encryption_key('1234567812345678')
        self.cipher_suite = Fernet(self.encryption_key)

        layout = BoxLayout(orientation='vertical')

        header_layout = BoxLayout(size_hint_y=None, height=50)
        title_label = Label(text='EncryptMeEasily Client 0.104', size_hint_x=0.95)
        close_button = Button(text='X', size_hint_x=None, width=50)
        close_button.bind(on_press=lambda x: self.stop())
        header_layout.add_widget(title_label)
        header_layout.add_widget(close_button)
        layout.add_widget(header_layout)

        # Content layout for log
        content_layout = BoxLayout(padding=[1], size_hint_y=None)
        self.info_log = Label(size_hint_y=None, markup=True, halign="left",
                              valign="bottom")  # Ensure this is initialized
        content_layout.add_widget(self.info_log)

        # ScrollView for logs
        log_scroll_view = CustomScrollView(size_hint=(1, 1), do_scroll_x=False)
        log_scroll_view.add_widget(content_layout)
        layout.add_widget(log_scroll_view)

        # Command input layout with new reset button
        command_input_layout = BoxLayout(size_hint_y=None, height=50, padding=[10])
        self.passkey_input = TextInput(multiline=False, hint_text='Please enter a username.')
        self.passkey_input.bind(on_text_validate=self.on_message_enter)

        # Add a reset button next to the TextInput
        reset_button = Button(text='New', size_hint_x=None, height=49, width=99)
        reset_button.bind(on_press=self.restart_process)
        command_input_layout.add_widget(self.passkey_input)
        command_input_layout.add_widget(reset_button)  # Add the reset button to the layout

        layout.add_widget(command_input_layout)

        return layout

    def restart_process(self, instance):
        if self.client_socket:
            try:
                self.client_socket.close()  # Attempt to close the socket connection if it exists
            except Exception as e:
                print(f"Error closing socket: {e}")
        self.client_socket = None
        self.setup_stage = 'username'
        self.passkey_input.text = ''  # Clear the input box
        self.passkey_input.hint_text = 'Please enter a username.'  # Reset hint text
        # Reset other UI elements as necessary, e.g., clear logs or messages

    def update_content_layout_height(self, *args):
        if not hasattr(self, 'content_layout'):
            return  # Make sure the content_layout attribute exists

        # Assuming 'content_layout' is the layout containing 'info_log'
        total_height = sum(child.height + self.content_layout.spacing for child in self.content_layout.children)
        self.content_layout.height = max(self.root.height,
                                         total_height)  # Ensure minimum height is the ScrollView's height
        self.content_layout.size_hint_y = None  # Disable size_hint to manually adjust height

    def handle_window_resize(self, instance, width, height):
        # Handle resizing logic here, for example:
        self.update_background()

    def generate_encryption_key(self, passkey):
        hasher = hashlib.sha256()
        hasher.update(passkey.encode('utf-8'))
        key = base64.urlsafe_b64encode(hasher.digest())
        return key

    def on_message_enter(self, instance):
        text = instance.text.strip()

        # Handle different setup stages
        if self.setup_stage == 'username':
            self.username = text
            self.setup_stage = 'server_ip'
            self.passkey_input.hint_text = 'Enter server IP or press Enter for localhost'
            self.info_log.text += '\nUsername set. Enter server IP or press Enter for localhost.'
        elif self.setup_stage == 'server_ip':
            self.server_address = text if text else '127.0.0.1'
            self.setup_stage = 'connect'
            self.connect_to_server()
        elif self.setup_stage == 'connect':
            self.setup_stage = 'passkey'
            self.passkey_input.hint_text = 'Enter passkey or press Enter for default'
            self.info_log.text += '\nConnected to the server. Enter passkey or press Enter for default:'
        elif self.setup_stage == 'passkey':
            # Generate encryption key based on the passkey or use the default
            self.encryption_key = self.generate_encryption_key(text if text else '1234567812345678')
            self.cipher_suite = Fernet(self.encryption_key)
            self.setup_stage = 'chat'
            self.passkey_input.hint_text = 'Enter message'
            self.send_username()  # Send the username now that we have established a secure channel
            self.info_log.text += '\nPasskey set. You can now enter messages.'
        elif self.setup_stage == 'chat':
            self.send_message(text)

        self.passkey_input.text = ''  # Clear the text input for next input

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_address, self.server_port))
            self.setup_stage = 'passkey'
            # Corrected from self.input_field to self.passkey_input
            self.passkey_input.hint_text = 'Enter passkey (press Enter for default key)'
            self.info_log.text += '\nConnected to the server. Please enter passkey.'
        except Exception as e:
            self.info_log.text += f'\nFailed to connect: {e}'
        if self.client_socket:
            self.listen_for_messages()  # Start the listening thread once connected

    def ensure_connection(self):
        try:
            # Attempt to send a small amount of data to check if socket is connected
            self.client_socket.send(b'')
        except OSError:
            # Handle disconnection or inability to send data
            print("Socket not connected, attempting to reconnect...")
            try:
                self.client_socket.connect((self.server_address, self.server_port))
                print("Reconnected to server.")
            except OSError as e:
                print(f"Failed to reconnect: {e}")
                return False
        return True

    def send_username(self):
        if self.ensure_connection():
            encrypted_username = self.cipher_suite.encrypt(self.username.encode('utf-8'))
            try:
                self.client_socket.send(encrypted_username)
            except Exception as e:
                print(f"Failed to send username: {e}")
        else:
            print("Not connected to server.")

    def send_message(self, message):
        if not message:
            print("No message to send.")
            return
        if not self.client_socket:
            print("Not connected to server.")
            return

        try:
            encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8'))
            self.client_socket.send(encrypted_message)
            print(f"Sent message: {message}")
        except Exception as e:
            print(f"Failed to send message: {e}")

    def listen_for_messages(self):
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    break
                message = self.cipher_suite.decrypt(encrypted_message).decode('utf-8')
                Clock.schedule_once(lambda dt: self.update_log(f"Friend: {message}"))
            except Exception as e:
                Clock.schedule_once(lambda dt: self.update_log("Connection lost with the server."))
                break

    def update_log(self, message):
        # Schedule the update to the info_log text on the main thread
        Clock.schedule_once(lambda dt: setattr(self.info_log, 'text', self.info_log.text + f'\n{message}'))

    def listen_for_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                message = self.cipher_suite.decrypt(encrypted_message).decode('utf-8')
                Clock.schedule_once(lambda dt: self.update_log(f"Friend: {message}"))
            except Exception as e:
                Clock.schedule_once(lambda dt: self.update_log("Connection lost with the server."))
                break

    def update_log(self, message):
        self.info_log.text += f'\n{message}'

if __name__ == '__main__':
    ClientApp().run()
