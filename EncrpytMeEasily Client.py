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
    def build(self):
        self.server_address = '127.0.0.1'
        self.server_port = 5000
        self.encryption_key = self.generate_encryption_key('defaultkey123')
        self.cipher_suite = Fernet(self.encryption_key)

        layout = BoxLayout(orientation='vertical')

        header_layout = BoxLayout(size_hint_y=None, height=50)
        title_label = Label(text='EncryptMeEasily Client 0.103', size_hint_x=0.95)
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
            Color(rgba=(0.0, 0.0, 0.0, 1))
            Rectangle(size=(Window.width, 50), pos=command_input_layout.pos)
        self.passkey_input = TextInput(multiline=False, hint_text='Enter passkey (4-16 digits) or press enter for the default test key.')
        self.passkey_input.bind(on_text_validate=self.on_message_enter)  # Correctly bind the event
        command_input_layout.add_widget(self.passkey_input)
        layout.add_widget(command_input_layout)

        return layout

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
        message = instance.text
        if not message:
            return

        if not hasattr(self, 'client_socket'):
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.server_address, self.server_port))
                threading.Thread(target=self.listen_for_messages, daemon=True).start()
                # Corrected: Use self.info_log instead of self.log_view
                self.info_log.text += '\nConnected to the server.'
            except Exception as e:
                # Corrected: Use self.info_log instead of self.log_view
                self.info_log.text += f'\nFailed to connect: {e}'
        else:
            encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8'))
            self.client_socket.send(encrypted_message)

        self.passkey_input.text = ''  # Assuming you want to clear the passkey input, not message_input which is not defined

    def update_log(self, message):
        # Schedule the update to the info_log text on the main thread
        Clock.schedule_once(lambda dt: setattr(self.info_log, 'text', self.info_log.text + f'\n{message}'))

    def listen_for_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                message = self.cipher_suite.decrypt(encrypted_message).decode('utf-8')
                Clock.schedule_once(lambda dt: self.update_log(message))
            except Exception as e:
                Clock.schedule_once(lambda dt: self.update_log("Lost connection to the server."))
                break

if __name__ == '__main__':
    ClientApp().run()
