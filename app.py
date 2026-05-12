#!/usr/bin/env python3
"""HTTP listener for App Runner TCP health checks plus connectivity logging to stdout."""

from __future__ import annotations

import http.server
import logging
import os
import platform
import socket
import subprocess
import sys
import threading
import time

DEFAULT_HOST = "scripts.cisco.com"


def configure_logging() -> logging.Logger:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return logging.getLogger("apprunner_connectivity")


log = configure_logging()


def target_host() -> str:
    return os.environ.get("CONNECTIVITY_TARGET_HOST", DEFAULT_HOST).strip() or DEFAULT_HOST


def run_ping(hostname: str) -> tuple[int, str]:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "4", hostname]
    else:
        cmd = ["ping", "-c", "4", "-W", "5", hostname]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
        )
        combined = "\n".join(
            part for part in (proc.stdout or "", proc.stderr or "") if part
        )
        return proc.returncode, combined.strip() or "(no ping output)"
    except FileNotFoundError:
        return 127, "ping binary not found (ICMP often unavailable in minimal/container images)"
    except subprocess.TimeoutExpired:
        return 124, "ping subprocess timed out"


def dns_resolve(hostname: str) -> str:
    try:
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        addrs = sorted({x[4][0] for x in infos})
        return ", ".join(addrs) if addrs else "no A/AAAA records returned"
    except OSError as exc:
        return f"DNS resolution failed: {exc}"


def tcp_probe(hostname: str, port: int = 443, timeout: float = 15.0) -> str:
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return f"TCP connect to {hostname}:{port} succeeded"
    except OSError as exc:
        return f"TCP connect to {hostname}:{port} failed: {exc}"


def log_connectivity_report() -> None:
    host = target_host()
    log.info("=== connectivity check start host=%s ===", host)

    code, ping_output = run_ping(host)
    log.info("ping finished exit_code=%s", code)
    for line in ping_output.splitlines():
        log.info("ping_output %s", line)
    if not ping_output.splitlines():
        log.info("ping_output %s", ping_output)

    if code != 0:
        log.warning(
            "ping did not exit 0 (ICMP is often blocked or unavailable in App Runner); "
            "see DNS/TCP below"
        )

    log.info("dns %s", dns_resolve(host))
    log.info("%s", tcp_probe(host, 443))
    log.info("=== connectivity check end ===")


class RequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        log.info("http %s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/health"):
            body = b"OK\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/check":
            log_connectivity_report()
            body = b"Check logged; see App Runner application logs in CloudWatch\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


def _startup_check() -> None:
    delay = float(os.environ.get("STARTUP_CHECK_DELAY_SEC", "2"))
    time.sleep(delay)
    log_connectivity_report()


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    log.info(
        "listener starting bind=0.0.0.0 port=%s target_host=%s",
        port,
        target_host(),
    )
    threading.Thread(target=_startup_check, daemon=True).start()
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), RequestHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
