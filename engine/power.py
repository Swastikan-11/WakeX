"""
WakeX Power Controller
Wraps the cross-platform OS power abstraction layer.
"""
from engine import os_power

def trigger_shutdown(delay_seconds: int = 0) -> dict:
    return os_power.execute_shutdown(delay_seconds)

def trigger_restart(delay_seconds: int = 0) -> dict:
    return os_power.execute_restart(delay_seconds)

def trigger_sleep() -> dict:
    return os_power.execute_sleep()

def trigger_hibernate() -> dict:
    return os_power.execute_hibernate()

def trigger_lock() -> dict:
    return os_power.execute_lock()

def trigger_unlock(credentials: str = "") -> dict:
    return os_power.execute_unlock(credentials)

def abort_shutdown() -> dict:

    return os_power.abort_shutdown()

def get_capabilities() -> dict:
    return os_power.get_supported_capabilities()
