"""TCP port scanning and service banner grabbing engine for subsweep-lead-scanner.

High-performance, non-blocking socket probing with ThreadPoolExecutor concurrency,
safe banner grabbing, SSL handshake inspection, and service fingerprinting.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

WEB_PORTS: List[int] = [80, 443, 8080, 8443, 3000, 5000, 8000]
INFRASTRUCTURE_PORTS: List[int] = [21, 22, 25, 53]
DATABASE_PORTS: List[int] = [3306, 5432, 6379, 27017]

DEFAULT_PORTS: List[int] = (
    WEB_PORTS + INFRASTRUCTURE_PORTS + DATABASE_PORTS
)

STANDARD_PORT_NAMES: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3000: "HTTP-Dev",
    3306: "MySQL",
    5000: "HTTP-Dev",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


@dataclass
class PortResult:
    """Result of probing an individual network port."""

    port: int
    state: str = "closed"  # 'open', 'closed', 'filtered', 'timeout', 'error'
    service: str = "unknown"
    banner: str = ""
    latency_ms: float = 0.0
    ssl: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize port result to dictionary."""
        return asdict(self)


@dataclass
class HostProbeSummary:
    """Consolidated report for all probed ports on a target host."""

    host: str
    ip: str = ""
    ports_scanned: int = 0
    open_ports: List[PortResult] = field(default_factory=list)
    closed_count: int = 0
    filtered_count: int = 0
    duration_seconds: float = 0.0
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize host probe summary to dictionary."""
        return {
            "host": self.host,
            "ip": self.ip,
            "ports_scanned": self.ports_scanned,
            "open_count": len(self.open_ports),
            "closed_count": self.closed_count,
            "filtered_count": self.filtered_count,
            "duration_seconds": round(self.duration_seconds, 3),
            "scanned_at": self.scanned_at,
            "open_ports": [p.to_dict() for p in self.open_ports],
        }


class PortProber:
    """Concurrent TCP port scanner with banner grabbing and fingerprinting."""

    def __init__(self, connect_timeout: float = 1.5, banner_timeout: float = 0.8) -> None:
        """Initialize port prober.

        Args:
            connect_timeout: Socket connect timeout in seconds.
            banner_timeout: Socket read timeout for banner extraction.
        """
        self.connect_timeout = connect_timeout
        self.banner_timeout = banner_timeout

    def resolve_target_ip(self, host: str) -> str:
        """Resolve hostname to primary IPv4 address."""
        try:
            return socket.gethostbyname(host)
        except Exception:
            return host

    def identify_service(self, port: int, banner: str) -> str:
        """Determine service name and version from port and captured banner text.

        Args:
            port: Network port number.
            banner: Raw banner text string.

        Returns:
            str: Descriptive service identifier.
        """
        b_lower = banner.lower()

        if "ssh" in b_lower:
            m = re.search(r"SSH-\d\.\d-([^\r\n]+)", banner)
            return f"SSH ({m.group(1).strip()})" if m else "SSH"

        if "ftp" in b_lower:
            m = re.search(r"220[- ]([^\r\n]+)", banner)
            return f"FTP ({m.group(1).strip()[:40]})" if m else "FTP"

        if "smtp" in b_lower or "esmtp" in b_lower or banner.startswith("220"):
            m = re.search(r"220[- ]([^\r\n]+)", banner)
            return f"SMTP ({m.group(1).strip()[:40]})" if m else "SMTP"

        if "+pong" in b_lower or "redis_version" in b_lower or "-noauth" in b_lower or "-err" in b_lower:
            return "Redis"

        if "mysql" in b_lower or "mariadb" in b_lower or "\x00" in banner:
            # Check for MySQL version string
            m = re.search(r"(\d+\.\d+\.\d+[-a-zA-Z0-9_]*)", banner)
            return f"MySQL ({m.group(1)})" if m else "MySQL"

        if "mongodb" in b_lower or "ismaster" in b_lower:
            return "MongoDB"

        if "server:" in b_lower or "http/" in b_lower:
            m = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
            server_name = m.group(1).strip() if m else "HTTP"
            if port in (443, 8443):
                return f"HTTPS ({server_name})"
            return f"HTTP ({server_name})"

        # Fallback to standard port name
        return STANDARD_PORT_NAMES.get(port, f"TCP/{port}")

    def _grab_banner(self, sock: socket.socket, host: str, port: int, is_ssl: bool = False) -> str:
        """Safely extract banner greeting or HTTP header from an open socket."""
        try:
            sock.settimeout(self.banner_timeout)

            if is_ssl or port in (443, 8443):
                # SSL Handshake & HTTP Request
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=host) as ssl_sock:
                        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: subsweep-prober\r\nConnection: close\r\n\r\n"
                        ssl_sock.sendall(req.encode("utf-8"))
                        data = ssl_sock.recv(1024)
                        return data.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

            if port in (80, 8080, 8000, 3000, 5000):
                req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: subsweep-prober\r\nConnection: close\r\n\r\n"
                sock.sendall(req.encode("utf-8"))
                data = sock.recv(1024)
                return data.decode("utf-8", errors="replace").strip()

            if port == 6379:
                sock.sendall(b"PING\r\n")
                data = sock.recv(512)
                return data.decode("utf-8", errors="replace").strip()

            # For passive banners like SSH / FTP / SMTP
            data = sock.recv(512)
            if data:
                return data.decode("utf-8", errors="replace").strip()

        except Exception:
            pass

        return ""

    def probe_port(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        grab_banner: bool = True,
    ) -> PortResult:
        """Probe a single TCP port on target host.

        Args:
            host: Target hostname or IP address.
            port: Port number to probe.
            timeout: Optional override for connect timeout.
            grab_banner: Whether to perform banner grabbing if port is open.

        Returns:
            PortResult: Outcome of port probe.
        """
        conn_timeout = timeout or self.connect_timeout
        start_time = time.perf_counter()
        is_ssl_port = port in (443, 8443)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(conn_timeout)

        try:
            sock.connect((host, port))
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            banner = ""
            if grab_banner:
                banner = self._grab_banner(sock, host, port, is_ssl=is_ssl_port)

            service_name = self.identify_service(port, banner)

            return PortResult(
                port=port,
                state="open",
                service=service_name,
                banner=banner,
                latency_ms=round(max(0.01, latency_ms), 2),
                ssl=is_ssl_port,
            )

        except (socket.timeout, TimeoutError):
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return PortResult(
                port=port,
                state="filtered",
                service=STANDARD_PORT_NAMES.get(port, f"TCP/{port}"),
                latency_ms=round(latency_ms, 2),
            )
        except ConnectionRefusedError:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return PortResult(
                port=port,
                state="closed",
                service=STANDARD_PORT_NAMES.get(port, f"TCP/{port}"),
                latency_ms=round(latency_ms, 2),
            )
        except OSError as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            err_str = str(exc).lower()
            if "timed out" in err_str or "timeout" in err_str:
                state = "filtered"
            else:
                state = "closed"
            return PortResult(
                port=port,
                state=state,
                service=STANDARD_PORT_NAMES.get(port, f"TCP/{port}"),
                latency_ms=round(latency_ms, 2),
            )
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def probe_host(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        timeout: Optional[float] = None,
        max_workers: int = 15,
        grab_banner: bool = True,
    ) -> HostProbeSummary:
        """Scan a list of TCP ports on target host concurrently.

        Args:
            host: Target hostname or IP.
            ports: Target ports (defaults to DEFAULT_PORTS).
            timeout: Connect timeout per port.
            max_workers: ThreadPool concurrency limit.
            grab_banner: Whether to grab service banners.

        Returns:
            HostProbeSummary: Summary report of scan.
        """
        start_time = time.perf_counter()
        target_ports = ports if ports is not None else DEFAULT_PORTS
        resolved_ip = self.resolve_target_ip(host)

        open_ports: List[PortResult] = []
        closed_count = 0
        filtered_count = 0

        workers = min(max_workers, max(1, len(target_ports)))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {
                executor.submit(
                    self.probe_port,
                    host,
                    p,
                    timeout or self.connect_timeout,
                    grab_banner,
                ): p
                for p in target_ports
            }

            for future in as_completed(future_to_port):
                res = future.result()
                if res.state == "open":
                    open_ports.append(res)
                elif res.state == "filtered":
                    filtered_count += 1
                else:
                    closed_count += 1

        # Sort open ports by port number
        open_ports.sort(key=lambda p: p.port)
        duration = time.perf_counter() - start_time

        return HostProbeSummary(
            host=host,
            ip=resolved_ip,
            ports_scanned=len(target_ports),
            open_ports=open_ports,
            closed_count=closed_count,
            filtered_count=filtered_count,
            duration_seconds=duration,
        )
