import logging
import threading
import time
import warnings

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

DEFAULT_URL = "https://www.roblox.com/home"  #


def launch(roblosecurity, url=DEFAULT_URL, launch_confirmation=True):
    # Suppress selenium annoying ahh logs
    logging.getLogger("selenium").setLevel(logging.CRITICAL)
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    # Make driver and disable logging
    options = Options()
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    driver = webdriver.Chrome(options=options)

    # Login with token
    driver.get("https://www.roblox.com")
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

    # Go to home page and make sure logged in
    driver.get("https://www.roblox.com/home")

    if launch_confirmation:
        WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )  # wait until loaded (gpt)

        # run swal.js to show a message (rly chopped rn but works fine)
        with open("swal.js", "r", encoding="utf-8") as f:
            script = f.read()
        driver.execute_script(script)

        if driver.current_url.lower().strip() != "https://www.roblox.com/login":
            driver.execute_script("""
                Swal.fire({
                    title: 'Success!',
                    text: 'You are now logged in, choose a game to play!',
                    icon: 'success',
                    confirmButtonText: 'OK'
                });
            """)
        else:
            # chopped ahh bro there has a to be a better way to do this
            driver.execute_script("""
                window.confirmResult = null;
                Swal.fire({
                    title: 'Error',
                    text: 'Failed to log in. Please check your .ROBLOSECURITY token.',
                    icon: 'error',
                    showCancelButton: true,
                    confirmButtonText: 'OK',
                    cancelButtonText: 'Close Page'
                }).then((result) => {
                    if (result.dismiss === Swal.DismissReason.cancel) {
                        window.confirmResult = 'cancel';
                    } else {
                        window.confirmResult = 'ok';
                    }
                });
            """)

            try:
                start = time.time()
                result = None
                while time.time() - start < 10:
                    result = driver.execute_script("return window.confirmResult;")
                    if result:
                        break
                    time.sleep(0.2)

                # Now handle result
                if result == "cancel":
                    driver.close()
            except Exception as e:
                print(f"Error handling confirmation: {e}")

    # Wait until the window is closed by user, then exit (help from gpt)
    try:
        while True:
            if len(driver.window_handles) == 0:
                break
            time.sleep(1)
    except Exception:
        pass

    driver.quit()


def launch_nonblocking(roblosecurity, url=DEFAULT_URL, launch_confirmation=True):
    thread = threading.Thread(target=launch, args=(roblosecurity, url, launch_confirmation), daemon=True)
    thread.start()
