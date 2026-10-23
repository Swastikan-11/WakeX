"""
WakeX Storage Utility
Provides atomic, crash-resilient JSON reads and writes with automatic backup fallbacks.
Prevents file corruption from sudden power cuts, system crashes, or ungraceful reboots.
"""
import os
import json
import tempfile
import logging
from typing import Any

logger = logging.getLogger("WakeX.Storage")

def atomic_write_json(file_path: str, data: Any, indent: int = 2) -> bool:
    """
    Atomically writes JSON data to a file using a temporary file and atomic replace.
    Ensures flush to disk (fsync) before replacing target file.
    Creates a .bak copy of any previous valid file for redundancy.
    """
    abs_path = os.path.abspath(file_path)
    dir_name = os.path.dirname(abs_path)
    os.makedirs(dir_name, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix="tmp_wakex_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        # If previous file exists, maintain a .bak copy
        bak_path = abs_path + ".bak"
        if os.path.exists(abs_path):
            try:
                # Copy existing to backup
                with open(abs_path, "rb") as src, open(bak_path, "wb") as dst:
                    dst.write(src.read())
            except Exception as e:
                logger.warning(f"Failed to create backup {bak_path}: {e}")

        # Atomic file replacement
        os.replace(tmp_path, abs_path)
        return True
    except Exception as e:
        logger.error(f"Error during atomic write to {abs_path}: {e}")
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        return False

def safe_read_json(file_path: str, default: Any = None) -> Any:
    """
    Safely reads JSON from disk. If the file is missing or corrupted,
    attempts to load from a .bak file before falling back to default.
    """
    abs_path = os.path.abspath(file_path)
    bak_path = abs_path + ".bak"

    if os.path.exists(abs_path):
        try:
            with open(abs_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Corrupted or invalid JSON in {abs_path}: {e}. Checking backup...")

    # Attempt backup recovery
    if os.path.exists(bak_path):
        try:
            with open(bak_path, "r", encoding="utf-8") as bf:
                recovered = json.load(bf)
                logger.warning(f"Successfully recovered JSON from backup {bak_path}")
                # Restore main file
                atomic_write_json(abs_path, recovered)
                return recovered
        except Exception as be:
            logger.error(f"Backup file {bak_path} also unreadable: {be}")

    return default
