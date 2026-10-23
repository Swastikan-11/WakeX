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
from logging.handlers import RotatingFileHandler
from PIL import Image

# Ensure working directory is the Hub root
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

# Local rotating logs with size limit (max 2MB, 2 backups, zero secrets)
log_handler = RotatingFileHandler(
    os.path.join(BASE_DIR, "wakex_hub.log"),
    maxBytes=2 * 1024 * 1024,
    backupCount=2,
    encoding="utf-8"
)
log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
log_handler.setFormatter(log_formatter)

logger = logging.getLogger("WakeX.HubLauncher")
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

PORT = 8000
_mutex_handle = None


def acquire_single_instance_mutex():
    """Win32 Named Mutex guard: prevents duplicate background tray and server instances."""
    global _mutex_handle
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            mutex = kernel32.CreateMutexW(None, False, "WakeX_Hub_SingleInstance_Mutex")
            if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
                logger.info("Another instance of WakeX Hub is already running. Focusing dashboard and exiting.")
                webbrowser.open(f"http://localhost:{PORT}")
                sys.exit(0)
            _mutex_handle = mutex
        except Exception as e:
            logger.warning(f"Single-instance mutex check error: {e}")


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
    # High-contrast Neon Red / Stealth Black fallback icon
    from PIL import ImageDraw
    img = Image.new('RGB', (64, 64), color=(5, 5, 8))
    d = ImageDraw.Draw(img)
    d.ellipse([8, 8, 56, 56], outline=(255, 42, 68), width=4)
    d.line([32, 16, 32, 34], fill=(255, 42, 68), width=4)
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


def is_start_on_boot_enabled() -> bool:
    """Checks whether WakeX is registered in HKCU Run registry."""
    if sys.platform != "win32":
        return False
    try:
        import winreg
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, "WakeX")
            return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def toggle_start_on_boot(icon=None, item=None):
    """Toggles HKCU Run registry autostart on Windows."""
    if sys.platform != "win32":
        return
    enabled = is_start_on_boot_enabled()
    try:
        import winreg
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                try:
                    winreg.DeleteValue(key, "WakeX")
                    logger.info("Start on Windows Boot disabled.")
                except FileNotFoundError:
                    pass
            else:
                exe_target = sys.executable if getattr(sys, "frozen", False) else os.path.join(BASE_DIR, "run_hub.bat")
                winreg.SetValueEx(key, "WakeX", 0, winreg.REG_SZ, f'"{exe_target}"')
                logger.info("Start on Windows Boot enabled.")
    except Exception as e:
        logger.error(f"Error toggling Start on Windows Boot: {e}")


def show_pairing_pin(icon=None, item=None):
    from engine import security
    code = security.generate_pairing_code()
    local_ip = get_local_ip()
    # Log event without logging the plain secret/PIN
    logger.info("Generated mobile pairing PIN from tray menu.")

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
    acquire_single_instance_mutex()

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
            pystray.MenuItem("🚀 Start on Windows Boot", toggle_start_on_boot, checked=lambda item: is_start_on_boot_enabled()),
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
