#!/usr/bin/env python3
"""HTTP listener for App Runner TCP health checks plus connectivity logging to stdout."""

from __future__ import annotations

import html
import http.server
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse

DEFAULT_HOST = "scripts.cisco.com"
MAX_HOST_LEN = 253
MAX_BODY_BYTES = 8192

# Hostname, IPv4, or bracketed IPv6 for ping argv (no shell).
_HOST_PATTERN = re.compile(
    r"^[\w.\-:\[\]]{1,253}$",
    re.ASCII,
)


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


def safe_log_fragment(value: str, limit: int = 400) -> str:
    """Reduce log injection risk from untrusted input (strip CR/LF, cap length)."""
    cleaned = value.replace("\r", " ").replace("\n", " ")
    if len(cleaned) > limit:
        return cleaned[: limit - 3] + "..."
    return cleaned


def validate_host(raw: str) -> str:
    host = raw.strip()
    if not host or len(host) > MAX_HOST_LEN:
        raise ValueError("Host must be 1–253 characters after trimming whitespace.")
    if not _HOST_PATTERN.fullmatch(host):
        raise ValueError(
            "Host may only contain letters, digits, dot, hyphen, colon, underscore, "
            "or brackets (for IPv6)."
        )
    return host


def validate_tcp_port(raw: str | None) -> int:
    if raw is None or str(raw).strip() == "":
        return 443
    try:
        port = int(str(raw).strip())
    except ValueError as exc:
        raise ValueError("TCP port must be an integer.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("TCP port must be between 1 and 65535.")
    return port


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


def dns_resolve(hostname: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
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


def run_connectivity(host: str, tcp_port: int) -> dict[str, object]:
    code, ping_output = run_ping(host)
    return {
        "host": host,
        "tcp_port": tcp_port,
        "ping_exit": code,
        "ping_output": ping_output,
        "dns": dns_resolve(host, tcp_port),
        "tcp": tcp_probe(host, tcp_port),
    }


def log_connectivity_report(host: str | None = None, tcp_port: int = 443) -> dict[str, object]:
    h = (host or target_host()).strip() or target_host()
    log.info("=== connectivity check start host=%s tcp_port=%s ===", h, tcp_port)
    result = run_connectivity(h, tcp_port)
    code = int(result["ping_exit"])
    ping_output = str(result["ping_output"])
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
    log.info("dns %s", result["dns"])
    log.info("%s", result["tcp"])
    log.info("=== connectivity check end ===")
    return result


def page_shell(title: str, inner_html: str) -> bytes:
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{html.escape(title)}</title>
<style>
  :root {{ font-family: system-ui, Segoe UI, Roboto, sans-serif; }}
  body {{ max-width: 52rem; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
  h1 {{ font-size: 1.35rem; }}
  label {{ display: block; margin: 0.75rem 0 0.25rem; font-weight: 600; }}
  input[type="text"], input[type="number"] {{
    width: 100%; max-width: 28rem; padding: 0.45rem 0.5rem; font-size: 1rem;
    box-sizing: border-box;
  }}
  button {{ margin-top: 1rem; padding: 0.5rem 1rem; font-size: 1rem; cursor: pointer; }}
  .hint {{ color: #444; font-size: 0.9rem; margin-top: 0.25rem; }}
  pre {{
    background: #f4f4f5; border: 1px solid #ddd; border-radius: 6px;
    padding: 1rem; overflow: auto; white-space: pre-wrap; word-break: break-word;
    font-size: 0.85rem;
  }}
  .error {{ color: #b00020; margin-top: 1rem; }}
  a {{ color: #0b5; }}
</style>
</head>
<body>
{inner_html}
</body>
</html>
"""
    return doc.encode("utf-8")


def form_fragment(default_host: str, default_port: int) -> str:
    return f"""
<h1>Connectivity check</h1>
<p>Enter a hostname or IP to run <strong>ping</strong> plus DNS and a <strong>TCP</strong> probe.
Results appear below and in <strong>App Runner application logs</strong> (CloudWatch).</p>
<form method="post" action="/test" autocomplete="off">
  <label for="host">Host</label>
  <input id="host" name="host" type="text" required maxlength="{MAX_HOST_LEN}"
         placeholder="e.g. scripts.cisco.com" value="{html.escape(default_host)}"/>
  <div class="hint">IPv4, hostname, or bracketed IPv6 (e.g. [::1]).</div>
  <label for="tcp_port">TCP port</label>
  <input id="tcp_port" name="tcp_port" type="number" min="1" max="65535"
         value="{default_port}"/>
  <div class="hint">Used for DNS/TCP probe (default 443).</div>
  <button type="submit">Run test</button>
</form>
<p class="hint">Startup still checks <code>{html.escape(target_host())}</code> once; use this form for any host.</p>
"""


def result_fragment(result: dict[str, object]) -> str:
    host = html.escape(str(result["host"]))
    port = int(result["tcp_port"])
    ping_exit = int(result["ping_exit"])
    ping_pre = html.escape(str(result["ping_output"]))
    dns_line = html.escape(str(result["dns"]))
    tcp_line = html.escape(str(result["tcp"]))
    status = "success" if ping_exit == 0 else "non-zero ping exit (see hints above)"
    return f"""
<h1>Results: {host}:{port}</h1>
<p><strong>Ping exit code:</strong> {ping_exit} ({html.escape(status)})</p>
<h2>Ping output</h2>
<pre>{ping_pre}</pre>
<h2>DNS (for TCP port {port})</h2>
<pre>{dns_line}</pre>
<h2>TCP</h2>
<pre>{tcp_line}</pre>
<p><a href="/">← New test</a></p>
"""


class RequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        log.info("http %s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/health":
            self._send(200, b"OK\n", "text/plain; charset=utf-8")
            return
        if path == "/check":
            log_connectivity_report()
            self._send(
                200,
                b"Default-host check logged; see App Runner application logs in CloudWatch.\n"
                b"Open / for the web UI to test any host.\n",
                "text/plain; charset=utf-8",
            )
            return
        if path == "/":
            qs = urllib.parse.parse_qs(parsed.query)
            default_h = target_host()
            default_p = 443
            if "host" in qs and qs["host"]:
                try:
                    default_h = validate_host(qs["host"][0])
                except ValueError:
                    default_h = target_host()
            if "tcp_port" in qs and qs["tcp_port"]:
                try:
                    default_p = validate_tcp_port(qs["tcp_port"][0])
                except ValueError:
                    default_p = 443
            err = ""
            if "error" in qs and qs["error"]:
                msg = safe_log_fragment(qs["error"][0], 300)
                err = f'<p class="error">{html.escape(msg)}</p>'
            inner = err + form_fragment(default_h, default_p)
            self._send(200, page_shell("Connectivity check", inner), "text/html; charset=utf-8")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.rstrip("/") != "/test":
            self.send_response(404)
            self.end_headers()
            return
        length_hdr = self.headers.get("Content-Length")
        try:
            length = int(length_hdr) if length_hdr else 0
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            loc = "/?error=" + urllib.parse.quote("Invalid or missing Content-Length.")
            self.send_response(303)
            self.send_header("Location", loc)
            self.end_headers()
            return
        raw = self.rfile.read(length)
        try:
            body = raw.decode("utf-8")
        except UnicodeDecodeError:
            loc = "/?error=" + urllib.parse.quote("Body must be UTF-8.")
            self.send_response(303)
            self.send_header("Location", loc)
            self.end_headers()
            return
        fields = urllib.parse.parse_qs(body, keep_blank_values=True)
        host_raw = (fields.get("host") or [""])[0]
        port_raw = (fields.get("tcp_port") or [""])[0]
        try:
            host = validate_host(host_raw)
            tcp_port = validate_tcp_port(port_raw)
        except ValueError as exc:
            loc = "/?error=" + urllib.parse.quote(str(exc))
            self.send_response(303)
            self.send_header("Location", loc)
            self.end_headers()
            return

        log.info(
            "ui_test requested host=%s tcp_port=%s",
            safe_log_fragment(host, 253),
            tcp_port,
        )
        result = log_connectivity_report(host=host, tcp_port=tcp_port)
        inner = form_fragment(host, tcp_port) + result_fragment(result)
        self._send(200, page_shell(f"Results: {host}", inner), "text/html; charset=utf-8")


def _startup_check() -> None:
    delay = float(os.environ.get("STARTUP_CHECK_DELAY_SEC", "2"))
    time.sleep(delay)
    log_connectivity_report()


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    log.info(
        "listener starting bind=0.0.0.0 port=%s default_target_host=%s",
        port,
        target_host(),
    )
    threading.Thread(target=_startup_check, daemon=True).start()
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), RequestHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
