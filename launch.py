import threading
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options


def launch(roblosecurity):
    options = Options()
    options.add_argument("--disable-blink-features=AutomationControlled")
    driver = webdriver.Chrome(options=options)

    # Navigate to Roblox to set cookies
    driver.get("https://www.roblox.com")

    # Set the .ROBLOSECURITY cookie manually
    driver.add_cookie(
        {
            "name": ".ROBLOSECURITY",
            "value": roblosecurity,
            "domain": ".roblox.com",
            "path": "/",
            "secure": True,
            "httpOnly": True,
        }
    )

    # Refresh with cookie applied
    driver.get("https://www.roblox.com/home")
    time.sleep(2)

    driver.execute_script('alert("You can now logged in, choose a game to play!");')

    # Wait until the window is closed by user, then fully exit
    try:
        while True:
            if len(driver.window_handles) == 0:
                break
            time.sleep(1)
    except Exception:
        pass

    print("Browser closed...")

    # Clean up
    driver.quit()


def launch_nonblocking(roblosecurity):
    thread = threading.Thread(target=launch, args=(roblosecurity,), daemon=True)
    thread.start()
