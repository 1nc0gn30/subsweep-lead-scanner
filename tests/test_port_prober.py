"""Unit tests for subsweep_lead_scanner.port_prober module."""

import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
from subsweep_lead_scanner.port_prober import (
    DATABASE_PORTS,
    DEFAULT_PORTS,
    INFRASTRUCTURE_PORTS,
    WEB_PORTS,
    HostProbeSummary,
    PortProber,
    PortResult,
)


@pytest.fixture
def prober() -> PortProber:
    """Instantiate PortProber instance."""
    return PortProber(connect_timeout=0.5, banner_timeout=0.3)


class TestServiceIdentification:
    """Test banner inspection and service classification logic."""

    def test_identify_ssh(self, prober):
        """Identify SSH daemon and version string."""
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        service = prober.identify_service(22, banner)
        assert "SSH" in service
        assert "OpenSSH_8.9p1" in service

    def test_identify_ftp(self, prober):
        """Identify FTP server banner."""
        banner = "220 (vsFTPd 3.0.3)\r\n"
        service = prober.identify_service(21, banner)
        assert "FTP" in service
        assert "vsFTPd" in service

    def test_identify_smtp(self, prober):
        """Identify SMTP mail transfer agent."""
        banner = "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"
        service = prober.identify_service(25, banner)
        assert "SMTP" in service
        assert "Postfix" in service

    def test_identify_redis(self, prober):
        """Identify Redis database response."""
        assert prober.identify_service(6379, "+PONG\r\n") == "Redis"
        assert prober.identify_service(6379, "-NOAUTH Authentication required.") == "Redis"

    def test_identify_mysql(self, prober):
        """Identify MySQL handshake greeting."""
        banner = "J\x00\x00\x00\n8.0.35-0ubuntu0.22.04.1\x00\x0c"
        service = prober.identify_service(3306, banner)
        assert "MySQL" in service
        assert "8.0.35" in service

    def test_identify_http_and_https(self, prober):
        """Identify HTTP/HTTPS servers from Server header."""
        http_banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"
        assert prober.identify_service(80, http_banner) == "HTTP (nginx/1.24.0)"
        assert prober.identify_service(443, http_banner) == "HTTPS (nginx/1.24.0)"


class TestSocketProbingWithLoopback:
    """Test socket probing using actual local loopback test sockets."""

    def test_probe_open_port(self, prober):
        """Probe an actively listening localhost TCP server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def handle_client():
            try:
                client, _ = server.accept()
                time.sleep(0.05)
                client.sendall(b"SSH-2.0-TestSSH_1.0\r\n")
                client.close()
            except Exception:
                pass

        th = threading.Thread(target=handle_client, daemon=True)
        th.start()

        try:
            res = prober.probe_port("127.0.0.1", port, timeout=1.0, grab_banner=True)
            assert res.state == "open"
            assert res.port == port
            assert res.latency_ms > 0
            assert "SSH" in res.service
        finally:
            server.close()

    def test_probe_closed_port(self, prober):
        """Probe an unused port on localhost that rejects connection."""
        # Find an unused port by binding and immediately closing
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.bind(("127.0.0.1", 0))
        unused_port = temp_sock.getsockname()[1]
        temp_sock.close()

        res = prober.probe_port("127.0.0.1", unused_port, timeout=0.5)
        assert res.state in ("closed", "filtered")


class TestConcurrentHostScan:
    """Test multi-port host scanning and summary report."""

    def test_probe_host_summary(self, prober):
        """Run multi-threaded host scan with mocked port results."""
        with patch.object(
            prober,
            "probe_port",
            side_effect=lambda host, port, timeout, grab_banner: (
                PortResult(port=port, state="open", service="HTTP", latency_ms=5.0)
                if port == 80
                else PortResult(port=port, state="closed", latency_ms=2.0)
            ),
        ):
            summary = prober.probe_host("example.com", ports=[80, 443, 8080], max_workers=3)

            assert isinstance(summary, HostProbeSummary)
            assert summary.host == "example.com"
            assert summary.ports_scanned == 3
            assert len(summary.open_ports) == 1
            assert summary.open_ports[0].port == 80
            assert summary.closed_count == 2
            assert summary.duration_seconds > 0

            # Check serialization
            data = summary.to_dict()
            assert data["host"] == "example.com"
            assert data["open_count"] == 1
            assert len(data["open_ports"]) == 1
