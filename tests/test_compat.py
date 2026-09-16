"""Unit tests for subsweep_lead_scanner.compat module."""

import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from subsweep_lead_scanner.compat import (
    atomic_write,
    get_platform_name,
    get_runtime_diagnostics,
    is_linux,
    is_macos,
    is_termux,
    is_windows,
    open_in_browser,
    setup_utf8_output,
    to_posix_path,
)


class TestPlatformDetection:
    """Test OS detection and platform abstraction functions."""

    def test_platform_consistency(self):
        """Current platform should identify consistently."""
        name = get_platform_name()
        assert isinstance(name, str)
        assert name in ("linux", "macos", "windows", "termux") or sys.platform.startswith(name)

    def test_is_windows_mock(self, monkeypatch):
        """Test Windows detection with monkeypatch."""
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(os, "name", "nt")
        assert is_windows() is True
        assert get_platform_name() == "windows"

    def test_is_macos_mock(self, monkeypatch):
        """Test macOS detection with monkeypatch."""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(os, "name", "posix")
        assert is_macos() is True
        assert get_platform_name() == "macos"

    def test_is_linux_mock(self, monkeypatch):
        """Test Linux detection with monkeypatch."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.delenv("TERMUX_VERSION", raising=False)
        monkeypatch.delenv("PREFIX", raising=False)
        with patch("os.path.exists", return_value=False):
            assert is_linux() is True
            assert is_macos() is False
            assert is_windows() is False

    def test_is_termux_mock(self, monkeypatch):
        """Test Termux Android environment detection."""
        monkeypatch.setenv("TERMUX_VERSION", "0.118.0")
        assert is_termux() is True
        assert get_platform_name() == "termux"


class TestUtf8Output:
    """Test UTF-8 console output configuration."""

    def test_setup_utf8_output(self):
        """Should configure stdout without crashing."""
        res = setup_utf8_output()
        assert isinstance(res, bool)


class TestPosixPath:
    """Test POSIX path normalization across platforms."""

    def test_to_posix_path_string(self):
        """Normalize string backslashes to forward slashes."""
        win_path = r"C:\Users\Admin\Documents\project\file.txt"
        posix = to_posix_path(win_path)
        assert posix == "C:/Users/Admin/Documents/project/file.txt"

    def test_to_posix_path_pathlib(self):
        """Accept Path objects and return POSIX representation."""
        p = Path("dir/subdir/file.json")
        assert to_posix_path(p) == "dir/subdir/file.json"


class TestAtomicWrite:
    """Test atomic file writing guarantees."""

    def test_atomic_write_text(self, tmp_path):
        """Atomically write text content."""
        target = tmp_path / "test_text.txt"
        content = "Hello, OSINT World!\nLine 2 with utf-8: 🚀"
        atomic_write(target, content)

        assert target.exists()
        assert target.read_text(encoding="utf-8") == content

    def test_atomic_write_nested_dirs(self, tmp_path):
        """Create parent directories automatically."""
        target = tmp_path / "deep" / "nested" / "dir" / "out.txt"
        atomic_write(target, "nested content")

        assert target.exists()
        assert target.read_text(encoding="utf-8") == "nested content"

    def test_atomic_write_binary(self, tmp_path):
        """Atomically write binary bytes."""
        target = tmp_path / "test_bin.bin"
        content = b"\x00\x01\x02\xFF\xFE"
        atomic_write(target, content, mode="wb")

        assert target.exists()
        assert target.read_bytes() == content

    def test_atomic_write_overwrite(self, tmp_path):
        """Atomically replace existing file without corrupting."""
        target = tmp_path / "overwrite.txt"
        atomic_write(target, "Version 1")
        assert target.read_text() == "Version 1"

        atomic_write(target, "Version 2")
        assert target.read_text() == "Version 2"


class TestOpenInBrowser:
    """Test browser invocation fallback logic."""

    @patch("webbrowser.open", return_value=True)
    def test_open_in_browser_url(self, mock_web_open):
        """Open web URL in browser."""
        res = open_in_browser("https://example.com")
        assert res is True
        mock_web_open.assert_called_once_with("https://example.com")

    @patch("shutil.which", return_value="/data/data/com.termux/files/usr/bin/termux-open-url")
    @patch("subprocess.run")
    def test_open_in_browser_termux(self, mock_run, mock_which, monkeypatch):
        """Open URL in Termux using termux-open-url."""
        monkeypatch.setenv("TERMUX_VERSION", "0.118")
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_run.return_value = mock_res

        res = open_in_browser("https://example.com")
        assert res is True
        mock_run.assert_called_once()


class TestRuntimeDiagnostics:
    """Test diagnostics report structure."""

    def test_get_runtime_diagnostics(self):
        """Check all required diagnostic keys exist."""
        diag = get_runtime_diagnostics()
        assert isinstance(diag, dict)
        assert "platform_name" in diag
        assert "python_version" in diag
        assert "has_ssl" in diag
        assert "has_ipv6" in diag
        assert "timestamp_utc" in diag
        assert "system" in diag
