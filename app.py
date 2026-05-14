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
MAX_BODY_BYTES = 262144
MAX_SCRIPT_QUERY_CHARS = 8000
MAX_PLAYGROUND_CONTENT_CHARS = 32000
MAX_API_RESPONSE_BODY_CHARS = 400_000

_DEFAULT_BDB_TOKEN_URL = (
    "https://sso-dbbfec7f.sso.duosecurity.com/oauth/DID1LHEMWQZDEGZ7FAXX/token"
)
_DEFAULT_SCRIPT_JOB_URL = "https://scripts.cisco.com/api/v2/jobs/Mykola_Cisco_Docs"
_DEFAULT_SCRIPT_QUERY = "How do i configure WxCC tenant"

_DEFAULT_PLAYGROUND_URL = "https://cxai-playground.cisco.com/chat/completions"
_DEFAULT_PLAYGROUND_SYSTEM = "Your name is Cisco Virtual Engineer"
_DEFAULT_PLAYGROUND_CONTENT = """Give me a funny joke for cisco networking engineers, only return the joke"""

_DEFAULT_DOCS_AI_URL = "https://docs-ai.cloudapps.cisco.com/api/v1/docs/ask"
_DEFAULT_DOCS_AI_QUESTION = "How to configure ACI?"
_DEFAULT_DOCS_AI_TRACE_HOST = "docs-ai.cloudapps.cisco.com"
MAX_DOCS_AI_QUESTION_CHARS = 8000

# ICMP / traceroute probe toward a well-known public address (default: Google DNS IPv4).
_PUBLIC_INTERNET_PROBE_HOST_DEFAULT = "8.8.8.8"

# Hostname, IPv4, or bracketed IPv6 for ping argv (no shell).
_HOST_PATTERN = re.compile(
    r"^[\w.\-:\[\]]{1,253}$",
    re.ASCII,
)

# HTTPS endpoints that return only the caller's public IP (first line) — fixed allowlist (SSRF-safe).
_EGRESS_IP_PROBES: tuple[tuple[str, str], ...] = (
    ("AWS checkip", "https://checkip.amazonaws.com/"),
    ("ipify", "https://api.ipify.org?format=text"),
)

# Fixed URL — Google connectivity / captive-portal style check (SSRF-safe allowlist).
_GOOGLE_GENERATE_204_URL = "https://connectivitycheck.gstatic.com/generate_204"


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


def _parse_plaintext_ip_response(body: str) -> str | None:
    """First line of body must be a valid IPv4 or IPv6 address."""
    if not (body or "").strip():
        return None
    line = body.strip().splitlines()[0].strip()
    candidate = line.split("%", 1)[0].strip()
    try:
        socket.inet_pton(socket.AF_INET, candidate)
        return candidate
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, candidate)
        return candidate
    except OSError:
        pass
    return None


def discover_egress_ip_rows() -> list[dict[str, str]]:
    """
    Outbound public IP as seen by fixed internet probes (same path as other HTTPS calls from this task).
    """
    timeout = float(os.environ.get("EGRESS_IP_PROBE_TIMEOUT_SEC", "8"))
    verify = requests_verify()
    rows: list[dict[str, str]] = []
    for label, url in _EGRESS_IP_PROBES:
        try:
            r = requests.get(url, timeout=timeout, verify=verify)
            ip = _parse_plaintext_ip_response(r.text or "")
            if r.ok and ip:
                rows.append(
                    {
                        "label": label,
                        "url": url,
                        "observed_ip": ip,
                        "status": "OK",
                        "notes": "",
                    }
                )
                log.info(
                    "egress_ip_probe label=%s observed_ip=%s http_status=%s",
                    label,
                    ip,
                    r.status_code,
                )
            else:
                preview = safe_log_fragment((r.text or "").replace("\n", " ")[:200], 200)
                rows.append(
                    {
                        "label": label,
                        "url": url,
                        "observed_ip": "—",
                        "status": f"HTTP {r.status_code}",
                        "notes": preview or "(empty or non-IP body)",
                    }
                )
                log.warning(
                    "egress_ip_probe label=%s http_status=%s invalid_body=%s",
                    label,
                    r.status_code,
                    bool((r.text or "").strip()),
                )
        except requests.RequestException as exc:
            rows.append(
                {
                    "label": label,
                    "url": url,
                    "observed_ip": "—",
                    "status": "Error",
                    "notes": safe_log_fragment(str(exc), 400),
                }
            )
            log.warning(
                "egress_ip_probe label=%s error=%s",
                label,
                safe_log_fragment(str(exc), 400),
            )
    return rows


def egress_ip_table_fragment(rows: list[dict[str, str]]) -> str:
    distinct = sorted({r["observed_ip"] for r in rows if r["observed_ip"] not in ("", "—")})
    summary = ", ".join(distinct) if distinct else "could not determine (see rows below)"
    hint = (
        "<p class=\"hint\">These probes show the <strong>public source IPv4/IPv6</strong> that "
        "external HTTPS endpoints see from <strong>this</strong> App Runner instance at request time. "
        "Default public egress addresses can <strong>change</strong>; for a stable allowlist use a "
        "VPC connector with <strong>NAT Gateway</strong> and an <strong>Elastic IP</strong> (or equivalent).</p>"
    )
    tr_parts: list[str] = []
    for r in rows:
        tr_parts.append(
            "<tr><td>"
            + html.escape(r["label"])
            + "</td><td><code>"
            + html.escape(r["url"])
            + "</code></td><td><code>"
            + html.escape(r["observed_ip"])
            + "</code></td><td>"
            + html.escape(r["status"])
            + "</td><td>"
            + html.escape(r["notes"])
            + "</td></tr>"
        )
    tbody = "\n".join(tr_parts)
    return f"""
<h2 style="font-size:1.1rem;">Outbound (egress) source IP</h2>
{hint}
<p><strong>Distinct observed IPs:</strong> <code>{html.escape(summary)}</code></p>
<table class="results" aria-label="Egress IP as seen by public probes">
<thead><tr><th>Probe</th><th>URL</th><th>Observed source IP</th><th>Status</th><th>Notes</th></tr></thead>
<tbody>
{tbody}
</tbody>
</table>
"""


def validate_script_query(raw: str | None) -> str:
    q = (raw or "").strip()
    if not q:
        q = _DEFAULT_SCRIPT_QUERY
    if "\x00" in q:
        raise ValueError("Query must not contain NUL bytes.")
    if len(q) > MAX_SCRIPT_QUERY_CHARS:
        raise ValueError(f"Query must be at most {MAX_SCRIPT_QUERY_CHARS} characters.")
    return q


def validate_playground_user_content(raw: str | None) -> str:
    c = (raw or "").strip()
    if not c:
        c = _DEFAULT_PLAYGROUND_CONTENT
    if "\x00" in c:
        raise ValueError("Playground user content must not contain NUL bytes.")
    if len(c) > MAX_PLAYGROUND_CONTENT_CHARS:
        raise ValueError(
            f"Playground user content must be at most {MAX_PLAYGROUND_CONTENT_CHARS} characters."
        )
    return c


def get_playground_api_key() -> str:
    """JWT / API key for cxai-playground (never log full value to CloudWatch)."""
    key = _env_pick_first(
        "PLAYGROUND_API_KEY",
        "CXAI_PLAYGROUND_API_KEY",
        "api_key",
        "API_KEY",
    )
    if not key:
        raise ValueError(
            "Missing playground API key. Set PLAYGROUND_API_KEY, CXAI_PLAYGROUND_API_KEY, "
            "api_key, or API_KEY on App Runner."
        )
    return key


def get_docs_ai_key() -> str:
    """Bearer token for docs-ai.cloudapps.cisco.com (never log full value to CloudWatch)."""
    key = _env_pick_first(
        "DOC_AI_KEY",
        "DOCS_AI_API_KEY",
        "DOCS_AI_KEY",
        "doc_AI_key",
    )
    if not key:
        raise ValueError(
            "Missing Docs AI API key. Set DOC_AI_KEY, DOCS_AI_API_KEY, DOCS_AI_KEY, or doc_AI_key on App Runner."
        )
    return key


def validate_docs_ai_question(raw: str | None) -> str:
    q = (raw or "").strip()
    if not q:
        q = _DEFAULT_DOCS_AI_QUESTION
    if "\x00" in q:
        raise ValueError("Docs AI question must not contain NUL bytes.")
    if len(q) > MAX_DOCS_AI_QUESTION_CHARS:
        raise ValueError(
            f"Docs AI question must be at most {MAX_DOCS_AI_QUESTION_CHARS} characters."
        )
    return q


def get_docs_ai_traceroute_target_host() -> str:
    """Hostname for traceroute/tracert toward Docs AI (override with DOCS_AI_TRACE_HOST)."""
    raw = (os.environ.get("DOCS_AI_TRACE_HOST") or _DEFAULT_DOCS_AI_TRACE_HOST).strip()
    return validate_host(raw)


def get_public_internet_probe_host() -> str:
    """IPv4/hostname for public-reachability ping + traceroute (override PUBLIC_INTERNET_PING_HOST)."""
    raw = (os.environ.get("PUBLIC_INTERNET_PING_HOST") or _PUBLIC_INTERNET_PROBE_HOST_DEFAULT).strip()
    return validate_host(raw)


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return float(str(raw).strip())
    except ValueError:
        return default


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


def run_traceroute(hostname: str) -> tuple[int, str]:
    """
    Windows: tracert. Linux: traceroute (iputils) with common flags; Fusion images often lack both.
    """
    system = platform.system().lower()
    timeout_sec = 180
    if system == "windows":
        cmd = ["tracert", "-d", "-h", "20", hostname]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            combined = "\n".join(
                part for part in (proc.stdout or "", proc.stderr or "") if part
            )
            return proc.returncode, combined.strip() or "(no tracert output)"
        except FileNotFoundError:
            return 127, "tracert not found in PATH."
        except subprocess.TimeoutExpired:
            return 124, "tracert subprocess timed out"

    linux_cmd_attempts: list[list[str]] = [
        ["traceroute", "-n", "-m", "20", "-q", "1", "-w", "2", hostname],
        ["traceroute", "-n", "-m", "20", hostname],
    ]
    for cmd in linux_cmd_attempts:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            combined = "\n".join(
                part for part in (proc.stdout or "", proc.stderr or "") if part
            )
            return proc.returncode, combined.strip() or "(no traceroute output)"
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            return 124, "traceroute subprocess timed out"
    return (
        127,
        "traceroute not found in PATH (typical on App Runner Fusion). "
        "Use the main form TCP connect timing to docs-ai.cloudapps.cisco.com:443 for reachability.",
    )


def log_traceroute_diagnostics(hostname: str) -> tuple[int, str]:
    """Run traceroute/tracert, log each line to stdout, return (exit_code, full_text) for the UI."""
    log.info("=== traceroute start host=%s ===", hostname)
    code, output = run_traceroute(hostname)
    log.info("traceroute finished exit_code=%s", code)
    for line in output.splitlines():
        log.info("traceroute_output %s", line)
    if not output.splitlines():
        log.info("traceroute_output %s", output)
    log.info("=== traceroute end ===")
    return code, output


def log_public_internet_ping(host: str) -> tuple[int, str]:
    """ICMP ping to public probe; log lines for CloudWatch."""
    log.info("=== public_internet_ping start host=%s ===", host)
    code, output = run_ping(host)
    log.info("public_internet_ping exit_code=%s", code)
    for line in output.splitlines():
        log.info("public_internet_ping_line %s", line)
    if not output.splitlines():
        log.info("public_internet_ping_line %s", output)
    log.info("=== public_internet_ping end ===")
    return code, output


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


def format_tcp_probe_block(title: str, hostname: str, port: int) -> str:
    timing, summary = tcp_rtt_probe(hostname, port)
    return f"{title}\n{summary}\n{timing}\n"


def run_https_get_smoke(url: str, log_purpose: str) -> str:
    """Single GET to a fixed allowlisted URL; logs status only (no body in CloudWatch)."""
    verify = requests_verify()
    timeout = float(os.environ.get("CONNECTIVITY_HTTP_TIMEOUT_SEC", "12"))
    log.info("%s start url=%s", log_purpose, safe_log_fragment(url, 240))
    t0 = time.perf_counter()
    try:
        r = requests.get(url, timeout=timeout, verify=verify, allow_redirects=True)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        n = len(r.content or b"")
        log.info(
            "%s complete http_status=%s elapsed_ms=%.1f response_bytes=%s",
            log_purpose,
            r.status_code,
            elapsed_ms,
            n,
        )
        return (
            f"HTTP status: {r.status_code}\n"
            f"Elapsed: {elapsed_ms:.1f} ms\n"
            f"Downloaded: {n} bytes (response body not echoed here)\n"
        )
    except requests.RequestException as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        log.warning(
            "%s failed elapsed_ms=%.1f err=%s",
            log_purpose,
            elapsed_ms,
            safe_log_fragment(repr(exc), 400),
        )
        return f"Failed after {elapsed_ms:.1f} ms\n{repr(exc)}\n"


def build_public_internet_python_diagnostics(host: str) -> str:
    """
    Fusion-friendly checks: TCP to common ports + HTTPS to Google generate_204.
    Does not require ping/traceroute binaries.
    """
    lines: list[str] = [
        "These use only Python stdlib sockets and requests (same runtime as your app).",
        "App Runner Fusion images usually omit ping/traceroute; that cannot be fixed from this repo",
        "without switching to a custom container image that installs iputils.",
        "",
        format_tcp_probe_block(f"TCP :443 → {host} (four timed connects)", host, 443),
        format_tcp_probe_block(
            f"TCP :53 → {host} (four timed connects; public DNS TCP path)", host, 53
        ),
        f"HTTPS GET {_GOOGLE_GENERATE_204_URL}",
        "(204 No Content is typical for this Google connectivity endpoint; any TLS success proves "
        "general HTTPS egress.)",
        run_https_get_smoke(_GOOGLE_GENERATE_204_URL, "public_internet_generate_204"),
    ]
    return "\n".join(lines)


def build_docs_ai_path_python_diagnostics(hostname: str) -> str:
    """TCP + HTTPS toward Docs AI host without ICMP."""
    root = f"https://{hostname}/"
    lines: list[str] = [
        "Same as above: works without ping/traceroute in the image.",
        "",
        format_tcp_probe_block(f"TCP :443 → {hostname}", hostname, 443),
        f"HTTPS GET {root}",
        "(Any HTTP response, including 401/403/404, usually means TLS + routing succeeded; "
        "compare with Docs AI POST errors.)",
        run_https_get_smoke(root, "docs_ai_https_root"),
    ]
    return "\n".join(lines)


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


def run_cxai_playground_chat_completions(user_content: str) -> str:
    """
    POST https://cxai-playground.cisco.com/chat/completions (Bearer JWT from env).
    Returns a single multi-line string for the UI. CloudWatch logs omit the API key and response body.
    """
    url = (os.environ.get("CXAI_PLAYGROUND_URL") or os.environ.get("PLAYGROUND_URL") or _DEFAULT_PLAYGROUND_URL).strip()
    model = (os.environ.get("PLAYGROUND_MODEL") or "gpt-4o-mini").strip()
    temperature = _float_env("PLAYGROUND_TEMPERATURE", 0.9)
    system_msg = (os.environ.get("PLAYGROUND_SYSTEM_MESSAGE") or _DEFAULT_PLAYGROUND_SYSTEM).strip() or _DEFAULT_PLAYGROUND_SYSTEM
    timeout = float(os.environ.get("PLAYGROUND_TIMEOUT_SEC", "120"))
    verify = requests_verify()
    api_key = get_playground_api_key()

    json_data: dict[str, object] = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_content},
        ],
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    lines: list[str] = []
    lines.append(f"POST {url}")
    lines.append("Headers:")
    lines.append("  Content-Type: application/json")
    lines.append(f"  Authorization: Bearer {api_key}")
    lines.append("")
    lines.append("Body (JSON):")
    lines.append(json.dumps(json_data, indent=2))

    log.info(
        "playground_chat start url=%s model=%s temperature=%s user_content_chars=%s ssl_verify=%s",
        safe_log_fragment(url, 500),
        safe_log_fragment(model, 80),
        temperature,
        len(user_content),
        verify if isinstance(verify, bool) else "custom_ca_bundle",
    )
    t0 = time.perf_counter()
    try:
        response = requests.post(
            url,
            headers=headers,
            json=json_data,
            timeout=timeout,
            verify=verify,
        )
    except requests.RequestException as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        lines.append("")
        lines.append(f"Request failed after {elapsed_ms:.1f} ms")
        lines.append(repr(exc))
        log.warning(
            "playground_chat transport_error elapsed_ms=%.1f error=%s",
            elapsed_ms,
            safe_log_fragment(repr(exc), 400),
        )
        return "\n".join(lines)

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    lines.append("")
    lines.append(f"HTTP status: {response.status_code}")
    lines.append(f"Elapsed: {elapsed_ms:.1f} ms")
    lines.append("Response body (raw):")
    lines.append(_truncate_for_display(response.text or ""))

    log.info(
        "playground_chat complete http_status=%s elapsed_ms=%.1f response_chars=%s",
        response.status_code,
        elapsed_ms,
        len(response.text or ""),
    )

    try:
        response_json = response.json()
    except ValueError:
        lines.append("")
        lines.append("Could not parse response as JSON; skipping choices[0].message.content extraction.")
        return "\n".join(lines)

    lines.append("")
    lines.append(
        "Extracted assistant message "
        "(response_json.get('choices')[0].get('message').get('content')):"
    )
    if not isinstance(response_json, dict):
        lines.append(f"(top-level JSON is not an object: {type(response_json).__name__})")
        return "\n".join(lines)
    choices = response_json.get("choices")
    if not isinstance(choices, list) or len(choices) == 0:
        lines.append("(missing or empty choices[])")
        return "\n".join(lines)
    first = choices[0]
    if not isinstance(first, dict):
        lines.append("(choices[0] is not an object)")
        return "\n".join(lines)
    message = first.get("message")
    if not isinstance(message, dict):
        lines.append("(choices[0].message is not an object)")
        return "\n".join(lines)
    content = message.get("content")
    if content is None:
        lines.append("(null content)")
    else:
        lines.append(str(content))

    return "\n".join(lines)


def run_docs_ai_ask(question: str) -> str:
    """
    POST https://docs-ai.cloudapps.cisco.com/api/v1/docs/ask with Bearer DOC_AI_KEY.
    Full request/response in UI; CloudWatch omits bearer token and body.
    """
    url = (os.environ.get("DOCS_AI_URL") or os.environ.get("DOCS_AI_ASK_URL") or _DEFAULT_DOCS_AI_URL).strip()
    timeout = float(os.environ.get("DOCS_AI_TIMEOUT_SEC", "120"))
    verify = requests_verify()
    api_key = get_docs_ai_key()

    body_obj: dict[str, object] = {"question": question}
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    lines: list[str] = []
    lines.append(f"POST {url}")
    lines.append("Headers:")
    lines.append("  Content-Type: application/json")
    lines.append(f"  Authorization: Bearer {api_key}")
    lines.append("")
    lines.append("Body (JSON):")
    lines.append(json.dumps(body_obj, indent=2))

    log.info(
        "docs_ai_ask start url=%s question_len=%s ssl_verify=%s",
        safe_log_fragment(url, 500),
        len(question),
        verify if isinstance(verify, bool) else "custom_ca_bundle",
    )
    t0 = time.perf_counter()
    try:
        response = requests.post(
            url,
            headers=headers,
            json=body_obj,
            timeout=timeout,
            verify=verify,
        )
    except requests.RequestException as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        lines.append("")
        lines.append(f"Request failed after {elapsed_ms:.1f} ms")
        exc_repr = repr(exc)
        lines.append(exc_repr)
        if "Errno 16" in exc_repr or "Device or resource busy" in exc_repr:
            lines.append("")
            lines.append(
                "Hint: errno 16 (EBUSY) on connect is often transient or indicates socket/kernel "
                "resource pressure (not a TLS certificate error). Try again after a few seconds, "
                "reduce parallel traffic from this instance, or enable “Run traceroute / tracert…” "
                "on this form for hop visibility (binary may be missing on Fusion)."
            )
        log.warning(
            "docs_ai_ask transport_error elapsed_ms=%.1f error=%s",
            elapsed_ms,
            safe_log_fragment(exc_repr, 400),
        )
        return "\n".join(lines)

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    lines.append("")
    lines.append(f"HTTP status: {response.status_code}")
    lines.append(f"Elapsed: {elapsed_ms:.1f} ms")
    lines.append("Response body (raw):")
    lines.append(_truncate_for_display(response.text or ""))

    log.info(
        "docs_ai_ask complete http_status=%s elapsed_ms=%.1f response_chars=%s",
        response.status_code,
        elapsed_ms,
        len(response.text or ""),
    )
    return "\n".join(lines)


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
  table.results {{
    border-collapse: collapse; width: 100%; max-width: 52rem; margin: 1rem 0; font-size: 0.9rem;
  }}
  table.results th, table.results td {{
    border: 1px solid #ccc; padding: 0.45rem 0.5rem; text-align: left; vertical-align: top;
  }}
  table.results th {{ background: #eee; }}
  table.results code {{ word-break: break-all; }}
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
    default_playground_content: str,
    run_playground_checked: bool,
    default_docs_ai_question: str,
    run_docs_ai_checked: bool,
    run_docs_ai_traceroute_checked: bool,
    run_public_internet_checked: bool,
) -> str:
    bdb_checked = " checked" if run_bdb_api_checked else ""
    pg_checked = " checked" if run_playground_checked else ""
    docs_checked = " checked" if run_docs_ai_checked else ""
    tr_checked = " checked" if run_docs_ai_traceroute_checked else ""
    pub_checked = " checked" if run_public_internet_checked else ""
    trace_host_hint = html.escape(
        (os.environ.get("DOCS_AI_TRACE_HOST") or _DEFAULT_DOCS_AI_TRACE_HOST).strip()
    )
    pub_host_hint = html.escape(
        (os.environ.get("PUBLIC_INTERNET_PING_HOST") or _PUBLIC_INTERNET_PROBE_HOST_DEFAULT).strip()
    )
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
  <h2 style="font-size:1.1rem;">Public internet check (optional)</h2>
  <p class="hint">Runs optional ICMP <strong>ping</strong> + <strong>tracert/traceroute</strong> toward
  <code>{pub_host_hint}</code> (default <code>8.8.8.8</code>) and <strong>always</strong> runs
  <strong>Python TCP</strong> probes (:443, :53) plus a small <strong>HTTPS GET</strong> to Google’s
  <code>generate_204</code> endpoint — those work on App Runner Fusion even when ping/traceroute binaries are missing.
  Override host with <code>PUBLIC_INTERNET_PING_HOST</code>.</p>
  <div class="row">
    <label>
      <input type="checkbox" name="run_public_internet_check" value="1"{pub_checked}/>
      Ping + tracert/traceroute to <code>{pub_host_hint}</code> (verify public internet path)
    </label>
  </div>
  <hr/>
  <h2 style="font-size:1.1rem;">Duo OAuth + Cisco script job (optional)</h2>
  <p class="hint">Uses <code>CLIENT_ID_*</code> / <code>CLIENT_SECRET_*</code> (or <code>client_id</code> /
  <code>client_secret</code>) from App Runner. Step logs appear in the page below and
  high-level metrics in CloudWatch (tokens and secrets are not written to application logs).</p>
  <div class="row">
    <label>
      <input type="checkbox" name="run_bdb_api" value="1"{bdb_checked}/>
      Also run Duo token + <code>Mykola_Cisco_Docs</code> script API test
    </label>
  </div>
  <label for="script_query">Script query (<code>input.query</code>)</label>
  <textarea id="script_query" name="script_query" maxlength="{MAX_SCRIPT_QUERY_CHARS}"
            placeholder="{html.escape(_DEFAULT_SCRIPT_QUERY)}">{html.escape(default_script_query)}</textarea>
  <hr/>
  <h2 style="font-size:1.1rem;">CX AI Playground — <code>chat/completions</code> (optional)</h2>
  <p class="hint">Same flow as your Python sample: <code>POST</code> to
  <code>cxai-playground.cisco.com/chat/completions</code> with <code>Authorization: Bearer …</code>.
  Set <code>PLAYGROUND_API_KEY</code> or <code>api_key</code> (or <code>API_KEY</code> / <code>CXAI_PLAYGROUND_API_KEY</code>)
  on App Runner. Full request/response is shown on this page; application logs do not include the JWT.</p>
  <div class="row">
    <label>
      <input type="checkbox" name="run_playground_api" value="1"{pg_checked}/>
      Also call CX AI Playground (<code>gpt-4o-mini</code> chat completions)
    </label>
  </div>
  <label for="playground_user_content">User message (<code>messages</code> user content)</label>
  <textarea id="playground_user_content" name="playground_user_content" maxlength="{MAX_PLAYGROUND_CONTENT_CHARS}"
            placeholder="{html.escape(_DEFAULT_PLAYGROUND_CONTENT)}">{html.escape(default_playground_content)}</textarea>
  <hr/>
  <h2 style="font-size:1.1rem;">Cisco Docs AI — <code>/api/v1/docs/ask</code> (optional)</h2>
  <p class="hint"><code>POST</code> to <code>docs-ai.cloudapps.cisco.com/api/v1/docs/ask</code> with
  <code>Authorization: Bearer …</code> and JSON body <code>{{"question":"…"}}</code>.
  Set <code>DOC_AI_KEY</code> (or <code>doc_AI_key</code> / <code>DOCS_AI_API_KEY</code> / <code>DOCS_AI_KEY</code>) on App Runner.
  Optional override: <code>DOCS_AI_URL</code>. Full request/response on this page only.</p>
  <div class="row">
    <label>
      <input type="checkbox" name="run_docs_ai_api" value="1"{docs_checked}/>
      Also call Docs AI <code>ask</code> API
    </label>
  </div>
  <label for="docs_ai_question">Question (<code>question</code> in JSON body)</label>
  <textarea id="docs_ai_question" name="docs_ai_question" maxlength="{MAX_DOCS_AI_QUESTION_CHARS}"
            placeholder="{html.escape(_DEFAULT_DOCS_AI_QUESTION)}">{html.escape(default_docs_ai_question)}</textarea>
  <div class="row">
    <label>
      <input type="checkbox" name="run_docs_ai_traceroute" value="1"{tr_checked}/>
      Run <strong>tracert</strong> (Windows) / <strong>traceroute</strong> (Linux) to <code>{trace_host_hint}</code>
    </label>
  </div>
  <p class="hint">Helps diagnose path to Docs AI when HTTPS fails. ICMP traceroute is usually missing on Fusion;
  this checkbox also runs <strong>Python TCP :443 + HTTPS GET</strong> to the same host below the traceroute output.
  Override host with <code>DOCS_AI_TRACE_HOST</code>.</p>
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


def playground_result_fragment(log: str) -> str:
    return f"""
<hr/>
<h1>CX AI Playground — chat completions</h1>
<pre>{html.escape(log)}</pre>
<p><a href="/">← New test</a></p>
"""


def docs_ai_result_fragment(log: str) -> str:
    return f"""
<hr/>
<h1>Cisco Docs AI — <code>/api/v1/docs/ask</code></h1>
<pre>{html.escape(log)}</pre>
<p><a href="/">← New test</a></p>
"""


def docs_ai_traceroute_result_fragment(
    hostname: str, exit_code: int, output: str, python_diag: str
) -> str:
    note = (
        "ICMP-based <code>tracert</code>/<code>traceroute</code> needs OS tools that App Runner’s "
        "managed Python (Fusion) image usually <strong>does not include</strong> — that is an AWS image "
        "choice, not something this app can enable without a <strong>custom Dockerfile</strong> (or bundling "
        "static binaries under <code>/app</code>). The section below is what actually works on Fusion."
    )
    return f"""
<hr/>
<h1>Path to Docs AI — ICMP + Python checks</h1>
<p class="hint">{note}</p>
<p><strong>Traceroute exit code:</strong> {exit_code} (127 = binary missing)</p>
<h2>Traceroute / tracert (often unavailable)</h2>
<pre>{html.escape(output)}</pre>
<h2>Python checks — TCP :443 + HTTPS (recommended)</h2>
<pre>{html.escape(python_diag)}</pre>
<p><a href="/">← New test</a></p>
"""


def public_internet_probe_result_fragment(
    host: str,
    ping_exit: int,
    ping_output: str,
    trace_exit: int,
    trace_output: str,
    python_diag: str,
) -> str:
    note = (
        "<strong>Ping/traceroute</strong> need separate programs; Fusion’s Python runtime typically has "
        "<strong>neither</strong> (exit 127). We cannot change the platform image from this repository. "
        "Use the <strong>Python checks</strong> below — TCP handshakes and a small HTTPS GET — to confirm "
        "general internet egress from this instance (closer to what your app does than ICMP)."
    )
    ping_note = (
        "ICMP ping reported success."
        if ping_exit == 0
        else (
            "Exit 127: no ping binary (expected on App Runner Fusion)."
            if ping_exit == 127
            else "ICMP ping did not complete successfully (may be blocked)."
        )
    )
    return f"""
<hr/>
<h1>Public internet — ICMP + Python checks to <code>{html.escape(host)}</code></h1>
<p class="hint">{note}</p>
<p><strong>Ping exit code:</strong> {ping_exit} — {html.escape(ping_note)}</p>
<h2>Ping (optional; often missing)</h2>
<pre>{html.escape(ping_output)}</pre>
<p><strong>Traceroute exit code:</strong> {trace_exit}</p>
<h2>Traceroute / tracert (optional; often missing)</h2>
<pre>{html.escape(trace_output)}</pre>
<h2>Python checks — TCP :443 / :53 + HTTPS (use on Fusion)</h2>
<pre>{html.escape(python_diag)}</pre>
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
            egress_rows = discover_egress_ip_rows()
            inner = (
                err
                + egress_ip_table_fragment(egress_rows)
                + form_fragment(
                    default_h,
                    default_p,
                    _DEFAULT_SCRIPT_QUERY,
                    False,
                    _DEFAULT_PLAYGROUND_CONTENT,
                    False,
                    _DEFAULT_DOCS_AI_QUESTION,
                    False,
                    False,
                    False,
                )
            )
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

        run_playground_api = bool(fields.get("run_playground_api"))
        playground_raw = (fields.get("playground_user_content") or [""])[0]
        playground_content_for_api = _DEFAULT_PLAYGROUND_CONTENT
        if run_playground_api:
            try:
                playground_content_for_api = validate_playground_user_content(playground_raw)
            except ValueError as exc:
                loc = "/?error=" + urllib.parse.quote(str(exc))
                self.send_response(303)
                self.send_header("Location", loc)
                self.end_headers()
                return

        display_playground_content = (
            playground_content_for_api
            if run_playground_api
            else (playground_raw.strip() or _DEFAULT_PLAYGROUND_CONTENT)
        )

        run_docs_ai_api = bool(fields.get("run_docs_ai_api"))
        docs_ai_question_raw = (fields.get("docs_ai_question") or [""])[0]
        docs_ai_question_for_api = _DEFAULT_DOCS_AI_QUESTION
        if run_docs_ai_api:
            try:
                docs_ai_question_for_api = validate_docs_ai_question(docs_ai_question_raw)
            except ValueError as exc:
                loc = "/?error=" + urllib.parse.quote(str(exc))
                self.send_response(303)
                self.send_header("Location", loc)
                self.end_headers()
                return

        display_docs_ai_question = (
            docs_ai_question_for_api
            if run_docs_ai_api
            else (docs_ai_question_raw.strip() or _DEFAULT_DOCS_AI_QUESTION)
        )

        run_docs_ai_traceroute = bool(fields.get("run_docs_ai_traceroute"))
        trace_target_host = _DEFAULT_DOCS_AI_TRACE_HOST
        if run_docs_ai_traceroute:
            try:
                trace_target_host = get_docs_ai_traceroute_target_host()
            except ValueError as exc:
                loc = "/?error=" + urllib.parse.quote(str(exc))
                self.send_response(303)
                self.send_header("Location", loc)
                self.end_headers()
                return

        run_public_internet_check = bool(fields.get("run_public_internet_check"))
        public_probe_host = _PUBLIC_INTERNET_PROBE_HOST_DEFAULT
        if run_public_internet_check:
            try:
                public_probe_host = get_public_internet_probe_host()
            except ValueError as exc:
                loc = "/?error=" + urllib.parse.quote(str(exc))
                self.send_response(303)
                self.send_header("Location", loc)
                self.end_headers()
                return

        log.info(
            "ui_test requested host=%s tcp_port=%s run_bdb_api=%s run_playground_api=%s "
            "run_docs_ai_api=%s run_docs_ai_traceroute=%s run_public_internet_check=%s",
            safe_log_fragment(host, 253),
            tcp_port,
            run_bdb_api,
            run_playground_api,
            run_docs_ai_api,
            run_docs_ai_traceroute,
            run_public_internet_check,
        )
        result = log_connectivity_report(host=host, tcp_port=tcp_port)
        egress_rows = discover_egress_ip_rows()
        inner = (
            form_fragment(
                host,
                tcp_port,
                display_script_query,
                run_bdb_api,
                display_playground_content,
                run_playground_api,
                display_docs_ai_question,
                run_docs_ai_api,
                run_docs_ai_traceroute,
                run_public_internet_check,
            )
            + egress_ip_table_fragment(egress_rows)
        )
        if run_public_internet_check:
            pub_ping_code, pub_ping_out = log_public_internet_ping(public_probe_host)
            pub_tr_code, pub_tr_out = log_traceroute_diagnostics(public_probe_host)
            pub_py = build_public_internet_python_diagnostics(public_probe_host)
            inner += public_internet_probe_result_fragment(
                public_probe_host,
                pub_ping_code,
                pub_ping_out,
                pub_tr_code,
                pub_tr_out,
                pub_py,
            )
        inner += result_fragment(result)
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
        if run_playground_api:
            try:
                plog = run_cxai_playground_chat_completions(playground_content_for_api)
            except ValueError as exc:
                plog = (
                    f"Configuration error:\n{exc}\n\n"
                    "Set PLAYGROUND_API_KEY, CXAI_PLAYGROUND_API_KEY, api_key, or API_KEY on the service."
                )
            inner += playground_result_fragment(plog)
        if run_docs_ai_traceroute:
            tcode, tout = log_traceroute_diagnostics(trace_target_host)
            docs_py = build_docs_ai_path_python_diagnostics(trace_target_host)
            inner += docs_ai_traceroute_result_fragment(trace_target_host, tcode, tout, docs_py)
        if run_docs_ai_api:
            try:
                dlog = run_docs_ai_ask(docs_ai_question_for_api)
            except ValueError as exc:
                dlog = (
                    f"Configuration error:\n{exc}\n\n"
                    "Set DOC_AI_KEY, DOCS_AI_API_KEY, DOCS_AI_KEY, or doc_AI_key on the service."
                )
            inner += docs_ai_result_fragment(dlog)

        self._send(200, page_shell(f"Results: {host}", inner), "text/html; charset=utf-8")


def _startup_check() -> None:
    delay = float(os.environ.get("STARTUP_CHECK_DELAY_SEC", "2"))
    time.sleep(delay)
    log_connectivity_report()
    rows = discover_egress_ip_rows()
    distinct = sorted({r["observed_ip"] for r in rows if r["observed_ip"] not in ("", "—")})
    log.info(
        "egress_ip_startup distinct_count=%s ips=%s",
        len(distinct),
        ",".join(distinct) if distinct else "(none)",
    )


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
