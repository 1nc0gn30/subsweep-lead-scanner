"""Cross-platform compatibility utilities for subsweep-lead-scanner.

Provides robust platform detection (Linux, macOS, Windows, Termux Android),
UTF-8 stdout configuration, atomic file operations, POSIX path normalization,
browser launching, and runtime environment diagnostics.
"""

from datetime import datetime, timezone
import io
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from typing import Any, Dict, Optional, Union
import webbrowser


def is_windows() -> bool:
    """Check if the current runtime is running on Microsoft Windows."""
    return sys.platform.startswith("win") or os.name == "nt"


def is_macos() -> bool:
    """Check if the current runtime is running on macOS (Darwin)."""
    return sys.platform == "darwin"


def is_termux() -> bool:
    """Check if the current runtime is running inside Termux on Android."""
    if os.environ.get("TERMUX_VERSION") or os.environ.get("TERMUX_APP_PID"):
        return True
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        return True
    return os.path.exists("/data/data/com.termux")


def is_linux() -> bool:
    """Check if the current runtime is running on Linux (including Termux)."""
    return sys.platform.startswith("linux") or os.name == "posix" and not is_macos()


def get_platform_name() -> str:
    """Return a normalized platform name string."""
    if is_termux():
        return "termux"
    if is_windows():
        return "windows"
    if is_macos():
        return "macos"
    if is_linux():
        return "linux"
    return sys.platform.lower()


def setup_utf8_output() -> bool:
    """Configure sys.stdout and sys.stderr for UTF-8 encoding safely across platforms.

    Returns:
        bool: True if stdout is configured with UTF-8 encoding, False otherwise.
    """
    configured = False
    try:
        if is_windows():
            # Enable ANSI escape sequences and UTF-8 console output codepage on Windows
            try:
                import ctypes
                kernel32 = getattr(ctypes, "windll", None)
                if kernel32 and hasattr(kernel32, "kernel32"):
                    kernel32.kernel32.SetConsoleOutputCP(65001)
                    kernel32.kernel32.SetConsoleCP(65001)
            except Exception:
                pass

        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            configured = True
        elif hasattr(sys.stdout, "buffer"):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
            configured = True

        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        elif hasattr(sys.stderr, "buffer"):
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        configured = False

    return configured or (getattr(sys.stdout, "encoding", "").lower() in ("utf-8", "utf8"))


def to_posix_path(path: Union[str, Path]) -> str:
    """Convert any filesystem path or string representation to a POSIX path.

    Replaces backslashes with forward slashes and normalizes drive letters.

    Args:
        path: Path or string to convert.

    Returns:
        str: POSIX formatted path string.
    """
    if isinstance(path, Path):
        return path.as_posix()
    path_str = str(path)
    return path_str.replace("\\", "/")


def atomic_write(
    filepath: Union[str, Path],
    content: Union[str, bytes],
    mode: str = "w",
    encoding: str = "utf-8",
) -> None:
    """Atomically write content to a file via a temporary file and atomic swap.

    Ensures that partial writes do not corrupt existing destination files.

    Args:
        filepath: Destination file path.
        content: String or bytes content to write.
        mode: Write mode ('w' for text, 'wb' for binary).
        encoding: Text encoding when writing string data.
    """
    target_path = Path(filepath).resolve()
    parent_dir = target_path.parent
    parent_dir.mkdir(parents=True, exist_ok=True)

    is_binary = "b" in mode or isinstance(content, bytes)
    temp_prefix = f".tmp_{target_path.name}_"

    temp_fd, temp_path_str = tempfile.mkstemp(prefix=temp_prefix, dir=parent_dir)
    temp_path = Path(temp_path_str)

    try:
        with os.fdopen(temp_fd, "wb" if is_binary else "w", encoding=None if is_binary else encoding) as f:
            if is_binary:
                if isinstance(content, str):
                    f.write(content.encode(encoding))
                else:
                    f.write(content)
            else:
                if isinstance(content, bytes):
                    f.write(content.decode(encoding, errors="replace"))
                else:
                    f.write(content)
            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_path, target_path)
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise


def open_in_browser(target: str) -> bool:
    """Open a URL or local file path in the system default browser.

    Handles Termux Android specific commands (termux-open-url / termux-open)
    before falling back to Python's standard `webbrowser` module.

    Args:
        target: URL string or local filepath.

    Returns:
        bool: True if command executed without error, False otherwise.
    """
    if is_termux():
        # Check for Termux URL / file opener commands
        for cmd in ("termux-open-url", "termux-open"):
            cmd_path = shutil.which(cmd)
            if cmd_path:
                try:
                    res = subprocess.run([cmd_path, target], capture_output=True, text=True, timeout=5)
                    if res.returncode == 0:
                        return True
                except Exception:
                    pass

    # Normalize local file target to file:// URI if applicable
    target_uri = target
    try:
        p = Path(target)
        if p.exists():
            target_uri = p.resolve().as_uri()
    except Exception:
        pass

    try:
        return bool(webbrowser.open(target_uri))
    except Exception:
        return False


def get_runtime_diagnostics() -> Dict[str, Any]:
    """Gather complete runtime diagnostics and system capabilities.

    Returns:
        Dict[str, Any]: Comprehensive diagnostic information.
    """
    ssl_available = False
    try:
        ctx = ssl.create_default_context()
        ssl_available = ctx is not None
    except Exception:
        ssl_available = False

    return {
        "platform_name": get_platform_name(),
        "is_linux": is_linux(),
        "is_macos": is_macos(),
        "is_windows": is_windows(),
        "is_termux": is_termux(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "stdout_encoding": getattr(sys.stdout, "encoding", "unknown"),
        "stderr_encoding": getattr(sys.stderr, "encoding", "unknown"),
        "default_encoding": sys.getdefaultencoding(),
        "filesystem_encoding": sys.getfilesystemencoding(),
        "has_ipv6": socket.has_ipv6,
        "has_ssl": ssl_available,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
