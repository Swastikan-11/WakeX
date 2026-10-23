"""
WakeX Hub Desktop Application & System Tray Supervisor
Double-click executable that runs WakeX 24/7 in the background with a system tray controller.
"""
import os
import sys
import time
import socket
import webbrowser
import threading
import logging
from PIL import Image

# Ensure working directory is the Hub root
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

logging.basicConfig(
    filename=os.path.join(BASE_DIR, "wakex_hub.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("WakeX.HubLauncher")

PORT = 8000

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0

def start_server_thread():
    if is_port_in_use(PORT):
        logger.info(f"WakeX Server is already running on port {PORT}.")
        return

    logger.info(f"Starting WakeX Server on port {PORT}...")
    try:
        import uvicorn
        from server import app
        config = uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level="warning", access_log=False)
        server = uvicorn.Server(config)
        server.run()
    except Exception as e:
        logger.critical(f"Server startup exception: {e}")

def get_tray_icon():
    icon_path = os.path.join(BASE_DIR, "static", "icon.png")
    if os.path.exists(icon_path):
        try:
            return Image.open(icon_path)
        except Exception:
            pass
    # Fallback generated icon
    from PIL import ImageDraw
    img = Image.new('RGB', (64, 64), color=(11, 15, 25))
    d = ImageDraw.Draw(img)
    d.ellipse([8, 8, 56, 56], outline=(245, 158, 11), width=4)
    return img

def open_dashboard(icon=None, item=None):
    webbrowser.open(f"http://localhost:{PORT}")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def open_mobile_url(icon=None, item=None):
    ip = get_local_ip()
    webbrowser.open(f"http://{ip}:{PORT}")

def show_pairing_pin(icon=None, item=None):
    from engine import security
    code = security.generate_pairing_code()
    local_ip = get_local_ip()
    logger.info(f"Generated mobile pairing PIN from tray menu: {code}")

    # Also open the dashboard with the code in view
    webbrowser.open(f"http://localhost:{PORT}/#pair-code={code}")

    # Display Topmost Windows Dialog with the 6-digit one-time code
    try:
        import ctypes
        msg = (
            f"WakeX Mobile Pairing PIN:\n\n"
            f"         {code}\n\n"
            f"Enter this 6-digit PIN on your phone in the WakeX app within 5 minutes.\n"
            f"Mobile Hub URL: http://{local_ip}:{PORT}\n\n"
            f"Security: 256-bit local encryption (Zero Cloud)."
        )
        ctypes.windll.user32.MessageBoxW(0, msg, "WakeX Device Pairing PIN", 0x00000040 | 0x00040000)
    except Exception as e:
        logger.warning(f"MessageBox error: {e}")

def on_exit(icon, item):
    logger.info("Exiting WakeX Hub from system tray...")
    icon.stop()
    os._exit(0)

def main():
    logger.info("==========================================")
    logger.info("      WakeX Hub Application Starting      ")
    logger.info("==========================================")

    # 1. Start Server in background daemon thread
    server_thread = threading.Thread(target=start_server_thread, daemon=True)
    server_thread.start()

    # Wait for server to bind
    for _ in range(30):
        if is_port_in_use(PORT):
            break
        time.sleep(0.1)

    # 2. Open dashboard on first launch
    open_dashboard()

    # 3. Setup System Tray
    try:
        import pystray
        local_ip = get_local_ip()

        menu = pystray.Menu(
            pystray.MenuItem("⚡ Open WakeX Dashboard", open_dashboard, default=True),
            pystray.MenuItem("🔑 Pair Mobile (Show One-Time PIN)", show_pairing_pin),
            pystray.MenuItem(f"📱 Mobile URL: http://{local_ip}:{PORT}", open_mobile_url),
            pystray.MenuItem(f"🟢 Status: 24/7 Active (Port {PORT})", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("❌ Exit WakeX Hub", on_exit)
        )

        icon = pystray.Icon("WakeX", get_tray_icon(), "WakeX Hub (Running 24/7)", menu)
        icon.run()
    except Exception as e:
        logger.warning(f"System tray could not be initialized: {e}. Running in headless supervisor mode.")
        # Headless supervisor loop
        while True:
            time.sleep(5)

if __name__ == "__main__":
    main()
