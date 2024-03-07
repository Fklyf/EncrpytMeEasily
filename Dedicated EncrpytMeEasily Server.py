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

kivy.require('2.0.0')

class NoMomentumScrollEffect(ScrollEffect):
    def update_velocity(self, dt):
        self.velocity = 0

Factory.register('NoMomentumScrollEffect', cls=NoMomentumScrollEffect)

class CustomScrollView(ScrollView):
    def __init__(self, **kwargs):
        super(CustomScrollView, self).__init__(**kwargs)
        self.effect_cls = 'NoMomentumScrollEffect'  # Remove momentum for scrolling
        self.scroll_type = ['bars', 'content']
        # Initial bar width can be set to 0 and adjusted dynamically based on content
        self.bar_width = 0
        Clock.schedule_once(self.check_content_size)
        Clock.schedule_once(self.init_ui)
        self.bind(size=self.check_content_size)  # Recheck when ScrollView size changes

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

class ServerApp(App):
    def build(self):
        self.server = ServerBackend(app=self)
        layout = BoxLayout(orientation='vertical')

        # Header layout
        header_layout = BoxLayout(size_hint_y=None, height=50)
        title_label = Label(text='EncryptMeEasily Server 0.103', size_hint_x=0.95)
        close_button = Button(text='X', size_hint_x=None, width=50)
        close_button.bind(on_press=lambda x: self.stop())
        header_layout.add_widget(title_label)
        header_layout.add_widget(close_button)
        layout.add_widget(header_layout)

        # Ensure dynamic resizing for the rectangle background (if necessary)
        command_input_layout = BoxLayout(size_hint_y=None, height=50, padding=[10])
        self.update_background = lambda *args: command_input_layout.canvas.before.clear()

        with command_input_layout.canvas.before:
            self.update_background()
            Color(rgba=(0.3, 0.3, 0.3, 1))
            Rectangle(size=(Window.width, 50), pos=command_input_layout.pos)

        Window.bind(on_resize=self.handle_window_resize)

        # Content layout for log
        content_layout = BoxLayout(padding=[10], size_hint_y=None)
        self.info_log = Label(size_hint_y=None, markup=True, halign="left", valign="bottom")
        self.info_log.bind(
            width=lambda *x: self.info_log.setter('text_size')(self.info_log, (self.info_log.width, None)),
            texture_size=lambda *x: self.update_content_layout_height(self.info_log.texture_size[1]))
        content_layout.add_widget(self.info_log)

        # ScrollView for logs
        log_scroll_view = CustomScrollView(size_hint=(1, 1), do_scroll_x=False)
        log_scroll_view.add_widget(content_layout)
        layout.add_widget(log_scroll_view)

        # Command input layout
        command_input_layout = BoxLayout(size_hint_y=None, height=50, padding=[10])
        with command_input_layout.canvas.before:
            Color(rgba=(0.3, 0.3, 0.3, 1))
            Rectangle(size=(Window.width, 50), pos=command_input_layout.pos)
        self.passkey_input = TextInput(multiline=False, hint_text='Enter passkey (4-16 digits) or press enter for the default test key.')
        self.passkey_input.bind(on_text_validate=self.on_passkey_enter)  # Correctly bind the event
        command_input_layout.add_widget(self.passkey_input)
        layout.add_widget(command_input_layout)

        # Control buttons layout
        control_layout = BoxLayout(size_hint_y=None, height=50)

        # Start Server button
        start_button = Button(text='Start Server')
        start_button.bind(on_press=self.start_server)  # Assuming start_server method is defined elsewhere
        control_layout.add_widget(start_button)

        # Stop Server button
        stop_button = Button(text='Stop Server')
        stop_button.bind(on_press=self.stop_server)  # Assuming stop_server method is defined elsewhere
        control_layout.add_widget(stop_button)

        # Kick All & Clear Log button
        kick_button = Button(text='Kick All & Clear Log')
        kick_button.bind(
            on_press=self.kick_all_and_clear_log)  # Assuming kick_all_and_clear_log method is defined elsewhere
        control_layout.add_widget(kick_button)

        layout.add_widget(control_layout)

        return layout

    def handle_window_resize(self, instance, width, height):
        # Handle resizing logic here, for example:
        self.update_background()

    def update_content_layout_height(self, height):
        """Update the height of the content layout to ensure it can scroll."""
        self.info_log.height = height  # Update the label height
        self.info_log.size_hint_y = None  # This allows the label to grow
        content_layout = self.info_log.parent  # Get the content layout
        if content_layout:
            content_layout.height = height + 20  # Add padding to height; adjust as needed

    def update_separator(self, instance, value):
        if hasattr(self, 'separator'):
            self.separator.pos = (instance.x, instance.y)
            self.separator.size = (instance.width, 1)

    def on_passkey_enter(self, instance):
        passkey = self.passkey_input.text
        if not passkey:
            passkey = '1234567812345678'
            self.server.generate_encryption_key([int(digit) for digit in passkey])
            self.update_info_log('Default passkey set. You can start the server now thank you.')
        elif 4 <= len(passkey) <= 16 and passkey.isdigit():
            self.server.generate_encryption_key([int(digit) for digit in passkey])
            self.update_info_log('Passkey set. You can start the server now thank you.')
        else:
            self.update_info_log('Invalid passkey. Please enter a number between 4 and 16 digits please.')
        self.passkey_input.text = ''

    @mainthread
    def update_info_log(self, message):
        self.info_log.text += f"\n{message}"

    def on_passkey_enter(self, instance):
        passkey = self.passkey_input.text
        if not passkey:
            passkey = '1234567812345678'
            self.server.generate_encryption_key([int(digit) for digit in passkey])
            self.update_info_log('Default passkey set. You can start the server now thank you.')
        elif 4 <= len(passkey) <= 16 and passkey.isdigit():
            self.server.generate_encryption_key([int(digit) for digit in passkey])
            self.update_info_log('Passkey set. You can start the server now thank you.')
        else:
            self.update_info_log('Invalid passkey. Please enter a number between 4 and 16 digits please.')
        self.passkey_input.text = ''

        self.server.generate_encryption_key([int(digit) for digit in passkey if digit.isdigit()])
        self.passkey_input.text = ''

    def start_server(self, instance):
        self.server.start_server()

    def stop_server(self, instance):
        self.server.stop_server()

    def kick_all_and_clear_log(self, instance):
        self.server.kick_all_clients()
        self.clear_logs()

    def clear_logs(self):
        self.info_log.text = ''

    def on_stop(self):
        self.server.stop_server()

class ServerBackend:
    def __init__(self, app):
        self.app = app
        self.server_socket = None
        self.is_active = False
        self.clients = []
        self.encryption_key = None
        self.cipher_suite = None

    def generate_encryption_key(self, seed_numbers):
        seed_string = ''.join(map(str, seed_numbers))
        hasher = hashlib.sha256()
        hasher.update(seed_string.encode('utf-8'))
        key = base64.urlsafe_b64encode(hasher.digest()[:32])
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
        threading.Thread(target=self.accept_connections, daemon=True).start()

    def accept_connections(self):
        while self.is_active:
            try:
                client_socket, address = self.server_socket.accept()
                self.app.update_info_log(f"Connection established with {address}")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True)
                client_thread.start()
                self.clients.append(client_socket)
            except Exception as e:
                if self.is_active:
                    self.app.update_info_log(f"Server stopped listening: {e}")
                break

    def handle_client(self, client_socket, address):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                decrypted_data = self.cipher_suite.decrypt(data).decode('utf-8')
                self.app.update_info_log(f"Message from {address}: {decrypted_data}")
                broadcast_encrypted = self.cipher_suite.encrypt(decrypted_data.encode('utf-8'))
                self.broadcast(broadcast_encrypted)
        except Exception as e:
            self.app.update_info_log(f"Error with client {address}: {e}")
        finally:
            client_socket.close()
            self.clients.remove(client_socket)
            self.app.update_info_log(f"Connection with {address} closed.")

    def broadcast(self, message):
        for client in self.clients:
            try:
                client.send(message)
            except Exception as e:
                self.app.update_info_log(f"Broadcast error to {client.getpeername()}: {e}")
                self.clients.remove(client)

    def stop_server(self):
        if self.is_active:
            self.is_active = False
            self.server_socket.close()
            self.app.update_info_log("Server stopped.")
            for client in self.clients:  # Corrected here
                try:
                    client.close()
                except Exception as e:
                    pass  # Optionally log this exception
            self.clients.clear()

    def kick_all_clients(self):
        for client in self.clients[:]:  # Corrected here
            try:
                client.close()
            except Exception as e:
                self.app.update_info_log(f"Error disconnecting {client.getpeername()}: {e}")
            self.clients.remove(client)
        self.app.update_info_log("")

if __name__ == '__main__':
    ServerApp().run()
