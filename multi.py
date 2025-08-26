from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw
import threading
import win32event
import win32con

# Create the mutex
mutex_name = "ROBLOX_singletonEvent"
mutex = win32event.CreateMutex(None, True, mutex_name)


def create_image():
    # Make a simple blank icon (red dot)
    image = Image.new("RGB", (64, 64), color="red")
    draw = ImageDraw.Draw(image)
    draw.ellipse((16, 16, 48, 48), fill="white")
    return image


def on_exit(icon, item):
    icon.stop()


def main():
    # Create system tray icon
    icon = Icon("Roblox MultiInstance")
    icon.icon = create_image()
    icon.title = "ROBLOX Multi-Instance"
    icon.menu = Menu(MenuItem("Exit", on_exit))
    icon.run()


# Run the icon in a thread so it doesn't block
threading.Thread(target=main).start()
