#!/usr/bin/env python3
"""HTTP listener for App Runner TCP health checks plus connectivity logging to stdout."""

from __future__ import annotations

import html
import http.server
import json
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

import requests

DEFAULT_HOST = "scripts.cisco.com"
MAX_HOST_LEN = 253
MAX_BODY_BYTES = 65536
MAX_SCRIPT_QUERY_CHARS = 8000
MAX_API_RESPONSE_BODY_CHARS = 400_000

_DEFAULT_BDB_TOKEN_URL = (
    "https://sso-dbbfec7f.sso.duosecurity.com/oauth/DID1LHEMWQZDEGZ7FAXX/token"
)
_DEFAULT_SCRIPT_JOB_URL = "https://scripts.cisco.com/api/v2/jobs/Mykola_Cisco_Docs"
_DEFAULT_SCRIPT_QUERY = "How do i configure WxCC tenant"

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
    logging.getLogger("urllib3").setLevel(logging.WARNING)
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


def _env_pick_first(*keys: str) -> str | None:
    for key in keys:
        val = os.environ.get(key)
        if val is not None and str(val).strip() != "":
            return str(val).strip()
    upper = {k.upper(): v for k, v in os.environ.items()}
    for key in keys:
        val = upper.get(key.upper())
        if val is not None and str(val).strip() != "":
            return str(val).strip()
    return None


def get_oauth_client_credentials() -> tuple[str, str]:
    """Same env aliases as AI_doc_Frontline (App Runner may use lowercase names)."""
    cid = _env_pick_first("CLIENT_ID_BDB", "CLIENT_ID", "client_id")
    csec = _env_pick_first("CLIENT_SECRET_BDB", "CLIENT_SECRET", "client_secret")
    if not cid or not csec:
        raise ValueError(
            "Missing OAuth client id/secret. Set CLIENT_ID_BDB, CLIENT_ID, or client_id "
            "and CLIENT_SECRET_BDB, CLIENT_SECRET, or client_secret on App Runner."
        )
    return cid, csec


def requests_verify() -> bool | str:
    raw = (os.environ.get("HTTP_SSL_VERIFY") or "true").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    bundle = (os.environ.get("SSL_CA_BUNDLE") or "").strip()
    if bundle:
        return bundle
    return True


def validate_script_query(raw: str | None) -> str:
    q = (raw or "").strip()
    if not q:
        q = _DEFAULT_SCRIPT_QUERY
    if "\x00" in q:
        raise ValueError("Query must not contain NUL bytes.")
    if len(q) > MAX_SCRIPT_QUERY_CHARS:
        raise ValueError(f"Query must be at most {MAX_SCRIPT_QUERY_CHARS} characters.")
    return q


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


def tcp_rtt_probe(
    hostname: str,
    port: int,
    count: int = 4,
    per_attempt_timeout: float = 10.0,
) -> tuple[str, str]:
    """Several timed TCP connects (like ping -c 4) when ICMP/ping is unavailable on Fusion."""
    lines: list[str] = []
    rtts_ms: list[float] = []
    for seq in range(1, count + 1):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((hostname, port), timeout=per_attempt_timeout):
                dt_ms = (time.perf_counter() - t0) * 1000.0
        except OSError as exc:
            lines.append(f"seq={seq} tcp_connect failed: {exc}")
            continue
        rtts_ms.append(dt_ms)
        lines.append(f"seq={seq} tcp_connect ok time_ms={dt_ms:.2f}")
    detail = "\n".join(lines) if lines else "(no tcp timing attempts)"
    if rtts_ms:
        mn, mx = min(rtts_ms), max(rtts_ms)
        avg = sum(rtts_ms) / len(rtts_ms)
        summary = (
            f"TCP {hostname}:{port} — {len(rtts_ms)}/{count} connects ok; "
            f"connect_time_ms min={mn:.2f} avg={avg:.2f} max={mx:.2f}"
        )
    else:
        summary = f"TCP {hostname}:{port} — 0/{count} connects succeeded"
    return detail, summary


def run_connectivity(host: str, tcp_port: int) -> dict[str, object]:
    code, ping_output = run_ping(host)
    tcp_timing, tcp_summary = tcp_rtt_probe(host, tcp_port)
    return {
        "host": host,
        "tcp_port": tcp_port,
        "ping_exit": code,
        "ping_output": ping_output,
        "dns": dns_resolve(host, tcp_port),
        "tcp_timing": tcp_timing,
        "tcp": tcp_summary,
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
    if code == 127:
        log.info(
            "ICMP ping skipped: no ping binary in PATH (App Runner Python/Fusion images "
            "typically ship only /app, not system iputils). Using TCP connect timing below."
        )
    elif code != 0:
        log.warning(
            "ICMP ping did not exit 0 (blocked or error); see DNS and TCP timing below"
        )
    log.info("dns %s", result["dns"])
    timing = str(result["tcp_timing"])
    for line in timing.splitlines():
        log.info("tcp_timing %s", line)
    log.info("%s", result["tcp"])
    log.info("=== connectivity check end ===")
    return result


def _truncate_for_display(text: str, limit: int = MAX_API_RESPONSE_BODY_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n… truncated for display ({len(text)} chars total)"


def run_duo_oauth_and_script_job(script_query: str) -> tuple[str, str]:
    """
    Step 1: Duo client_credentials token.
    Step 2: Cisco BDB script job with Bearer token.

    Returns (step1_full_log, step2_full_log) for the UI. CloudWatch logs omit secrets/tokens.
    """
    token_url = (os.environ.get("BDB_TOKEN_URL") or _DEFAULT_BDB_TOKEN_URL).strip()
    script_url = (os.environ.get("CISCO_SCRIPT_JOB_URL") or _DEFAULT_SCRIPT_JOB_URL).strip()
    timeout_token = float(os.environ.get("BDB_TOKEN_TIMEOUT_SEC", "60"))
    timeout_script = float(os.environ.get("BDB_SCRIPT_TIMEOUT_SEC", "120"))
    verify = requests_verify()

    cid, csec = get_oauth_client_credentials()

    step1: list[str] = []
    step1.append(f"POST {token_url}")
    step1.append("Headers:")
    step1.append("  Content-Type: application/x-www-form-urlencoded")
    step1.append("")
    step1.append("Body (application/x-www-form-urlencoded):")
    step1.append(
        urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": cid,
                "client_secret": "(redacted — value sent from CLIENT_SECRET_* / client_secret env)",
            }
        )
    )
    step1.append("")
    step1.append("(Actual request sends the real client_secret from environment; it is not echoed here.)")

    log.info(
        "bdb_api step1 start token_url=%s client_id_len=%s ssl_verify=%s",
        safe_log_fragment(token_url, 500),
        len(cid),
        verify if isinstance(verify, bool) else "custom_ca_bundle",
    )
    t0 = time.perf_counter()
    try:
        r1 = requests.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": cid,
                "client_secret": csec,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout_token,
            verify=verify,
        )
    except requests.RequestException as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        step1.append("")
        step1.append(f"Request failed after {elapsed_ms:.1f} ms")
        step1.append(repr(exc))
        log.warning(
            "bdb_api step1 transport_error elapsed_ms=%.1f error=%s",
            elapsed_ms,
            safe_log_fragment(repr(exc), 400),
        )
        return "\n".join(step1), "(Step 2 skipped — token request did not complete.)"

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    step1.append("")
    step1.append(f"HTTP status: {r1.status_code}")
    step1.append(f"Elapsed: {elapsed_ms:.1f} ms")
    step1.append("Response body:")
    step1.append(_truncate_for_display(r1.text or ""))

    log.info(
        "bdb_api step1 complete http_status=%s elapsed_ms=%.1f response_chars=%s",
        r1.status_code,
        elapsed_ms,
        len(r1.text or ""),
    )

    if not r1.ok:
        log.warning("bdb_api step1 non_success http_status=%s", r1.status_code)
        return "\n".join(step1), "(Step 2 skipped — token HTTP status was not success.)"

    try:
        payload = r1.json()
    except ValueError:
        log.warning("bdb_api step1 json_parse_failed")
        step1.append("")
        step1.append("Could not parse JSON; cannot read access_token for step 2.")
        return "\n".join(step1), "(Step 2 skipped — token response was not JSON.)"

    token: str | None = None
    if isinstance(payload, dict):
        raw_t = payload.get("access_token")
        if isinstance(raw_t, str) and raw_t.strip():
            token = raw_t.strip()

    if not token:
        log.warning(
            "bdb_api step1 missing_access_token keys=%s",
            list(payload.keys()) if isinstance(payload, dict) else type(payload).__name__,
        )
        step1.append("")
        step1.append("JSON parsed but access_token missing or empty.")
        return "\n".join(step1), "(Step 2 skipped — no access_token in token response.)"

    log.info("bdb_api step1 token_ok access_token_chars=%s", len(token))

    body_obj: dict[str, object] = {"dev": "true", "input": {"query": script_query}}
    body_json = json.dumps(body_obj, indent=2)

    step2_lines: list[str] = []
    step2_lines.append(f"POST {script_url}")
    step2_lines.append("Headers:")
    step2_lines.append("  Content-Type: application/json")
    step2_lines.append(f"  Authorization: Bearer {token}")
    step2_lines.append("")
    step2_lines.append("Body (raw JSON):")
    step2_lines.append(body_json)

    log.info(
        "bdb_api step2 start script_url=%s query_len=%s ssl_verify=%s",
        safe_log_fragment(script_url, 500),
        len(script_query),
        verify if isinstance(verify, bool) else "custom_ca_bundle",
    )
    t1 = time.perf_counter()
    try:
        r2 = requests.post(
            script_url,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            },
            json=body_obj,
            timeout=timeout_script,
            verify=verify,
        )
    except requests.RequestException as exc:
        elapsed2 = (time.perf_counter() - t1) * 1000.0
        step2_lines.append("")
        step2_lines.append(f"Request failed after {elapsed2:.1f} ms")
        step2_lines.append(repr(exc))
        log.warning(
            "bdb_api step2 transport_error elapsed_ms=%.1f error=%s",
            elapsed2,
            safe_log_fragment(repr(exc), 400),
        )
        return "\n".join(step1), "\n".join(step2_lines)

    elapsed2 = (time.perf_counter() - t1) * 1000.0
    step2_lines.append("")
    step2_lines.append(f"HTTP status: {r2.status_code}")
    step2_lines.append(f"Elapsed: {elapsed2:.1f} ms")
    step2_lines.append("Response body:")
    step2_lines.append(_truncate_for_display(r2.text or ""))

    log.info(
        "bdb_api step2 complete http_status=%s elapsed_ms=%.1f response_chars=%s",
        r2.status_code,
        elapsed2,
        len(r2.text or ""),
    )
    return "\n".join(step1), "\n".join(step2_lines)


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
  textarea {{
    width: 100%; max-width: 40rem; min-height: 6rem; padding: 0.45rem 0.5rem;
    font-size: 0.95rem; box-sizing: border-box; font-family: inherit;
  }}
  .row {{ margin: 0.5rem 0; }}
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


def form_fragment(
    default_host: str,
    default_port: int,
    default_script_query: str,
    run_bdb_api_checked: bool,
) -> str:
    checked = " checked" if run_bdb_api_checked else ""
    return f"""
<h1>Connectivity check</h1>
<p>Enter a hostname or IP. The service runs <strong>ICMP ping</strong> when the image has a
<code>ping</code> binary; on App Runner managed Python (Fusion) only <code>/app</code> is copied,
so ICMP is usually unavailable and we run <strong>four timed TCP connects</strong> to your port instead
(similar idea to <code>ping -c 4</code>). DNS and logs always run.</p>
<form method="post" action="/test" autocomplete="off">
  <label for="host">Host</label>
  <input id="host" name="host" type="text" required maxlength="{MAX_HOST_LEN}"
         placeholder="e.g. scripts.cisco.com" value="{html.escape(default_host)}"/>
  <div class="hint">IPv4, hostname, or bracketed IPv6 (e.g. [::1]).</div>
  <label for="tcp_port">TCP port</label>
  <input id="tcp_port" name="tcp_port" type="number" min="1" max="65535"
         value="{default_port}"/>
  <div class="hint">Used for DNS/TCP probe (default 443).</div>
  <hr/>
  <h2 style="font-size:1.1rem;">Duo OAuth + Cisco script job (optional)</h2>
  <p class="hint">Uses <code>CLIENT_ID_*</code> / <code>CLIENT_SECRET_*</code> (or <code>client_id</code> /
  <code>client_secret</code>) from App Runner. Step logs appear in the page below and
  high-level metrics in CloudWatch (tokens and secrets are not written to application logs).</p>
  <div class="row">
    <label>
      <input type="checkbox" name="run_bdb_api" value="1"{checked}/>
      Also run Duo token + <code>Mykola_Cisco_Docs</code> script API test
    </label>
  </div>
  <label for="script_query">Script query (<code>input.query</code>)</label>
  <textarea id="script_query" name="script_query" maxlength="{MAX_SCRIPT_QUERY_CHARS}"
            placeholder="{html.escape(_DEFAULT_SCRIPT_QUERY)}">{html.escape(default_script_query)}</textarea>
  <button type="submit">Run test</button>
</form>
<p class="hint">Startup still checks <code>{html.escape(target_host())}</code> once; use this form for any host.</p>
"""


def result_fragment(result: dict[str, object]) -> str:
    host = html.escape(str(result["host"]))
    port = int(result["tcp_port"])
    ping_exit = int(result["ping_exit"])
    ping_pre = html.escape(str(result["ping_output"]))
    timing_pre = html.escape(str(result["tcp_timing"]))
    dns_line = html.escape(str(result["dns"]))
    tcp_line = html.escape(str(result["tcp"]))
    if ping_exit == 0:
        icmp_note = "ICMP ping reported success."
    elif ping_exit == 127:
        icmp_note = "Exit 127: no ping binary (normal on App Runner Fusion); use TCP timing below."
    else:
        icmp_note = "ICMP ping did not succeed; use TCP timing below."
    return f"""
<h1>Results: {host}:{port}</h1>
<p><strong>ICMP ping exit code:</strong> {ping_exit} — {html.escape(icmp_note)}</p>
<h2>ICMP ping (subprocess)</h2>
<pre>{ping_pre}</pre>
<h2>TCP connect timing (4 attempts to port {port})</h2>
<pre>{timing_pre}</pre>
<h2>DNS (for TCP port {port})</h2>
<pre>{dns_line}</pre>
<h2>TCP summary</h2>
<pre>{tcp_line}</pre>
<p><a href="/">← New test</a></p>
"""


def bdb_api_result_fragment(step1_log: str, step2_log: str) -> str:
    return f"""
<hr/>
<h1>Duo OAuth + Cisco script job</h1>
<h2>Step 1 — POST token (client_credentials)</h2>
<pre>{html.escape(step1_log)}</pre>
<h2>Step 2 — POST Mykola_Cisco_Docs</h2>
<pre>{html.escape(step2_log)}</pre>
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
            inner = err + form_fragment(default_h, default_p, _DEFAULT_SCRIPT_QUERY, False)
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

        run_bdb_api = bool(fields.get("run_bdb_api"))
        script_query_raw = (fields.get("script_query") or [""])[0]
        script_query_for_api = _DEFAULT_SCRIPT_QUERY
        if run_bdb_api:
            try:
                script_query_for_api = validate_script_query(script_query_raw)
            except ValueError as exc:
                loc = "/?error=" + urllib.parse.quote(str(exc))
                self.send_response(303)
                self.send_header("Location", loc)
                self.end_headers()
                return

        display_script_query = (
            script_query_for_api if run_bdb_api else (script_query_raw.strip() or _DEFAULT_SCRIPT_QUERY)
        )

        log.info(
            "ui_test requested host=%s tcp_port=%s run_bdb_api=%s",
            safe_log_fragment(host, 253),
            tcp_port,
            run_bdb_api,
        )
        result = log_connectivity_report(host=host, tcp_port=tcp_port)
        inner = (
            form_fragment(host, tcp_port, display_script_query, run_bdb_api)
            + result_fragment(result)
        )
        if run_bdb_api:
            try:
                s1, s2 = run_duo_oauth_and_script_job(script_query_for_api)
            except ValueError as exc:
                s1 = (
                    f"Configuration error:\n{exc}\n\n"
                    "Set CLIENT_ID_BDB / CLIENT_ID / client_id and "
                    "CLIENT_SECRET_BDB / CLIENT_SECRET / client_secret on the service."
                )
                s2 = "(Step 2 skipped — OAuth credentials are not configured.)"
            inner += bdb_api_result_fragment(s1, s2)

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
