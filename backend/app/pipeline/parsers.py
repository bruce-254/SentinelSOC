"""Log source parsers.

Each parser turns raw log text into a structured parse result (a dict with the
fields that normalizer understands). Parsers are defensive: malformed lines
raise ``ParseError`` rather than crashing the pipeline, and callers decide how
to handle rejection.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from ..core.errors import BadRequest


class ParseError(Exception):
    """Raised when a raw log line cannot be parsed."""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def is_ip(v: str | None) -> bool:
    if not v:
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def norm_ip(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip().strip('"').strip("'")
    if is_ip(v):
        return v
    return None


def parse_timestamp(v: str | None) -> datetime | None:
    """Best-effort timestamp parsing across common formats."""
    if not v:
        return None
    v = v.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    fmt = None
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        pass
    # Try a set of common formats (without tz -> assume UTC).
    candidates = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
    ]
    for f in candidates:
        try:
            return datetime.strptime(v, f).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_syslog_ts(token: str) -> datetime | None:
    """Parse 'Jun 12 10:30:45' style syslog timestamp (no year -> current year)."""
    m = re.match(r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", token)
    if not m:
        return None
    mon = MONTHS.get(m.group(1))
    if not mon:
        return None
    day, hh, mm, ss = int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
    year = datetime.now(timezone.utc).year
    try:
        return datetime(year, mon, day, hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# 1. Linux authentication logs
# --------------------------------------------------------------------------
def parse_linux_auth(raw: str, source_log_type: str) -> dict:
    # Example:
    # Jun 12 10:30:45 srv01 sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2
    # Jun 12 10:30:46 srv01 sshd[1235]: Accepted password for alice from 10.0.0.5 port 2222 ssh2
    # Jun 12 10:31:00 srv01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
    # Jun 12 10:32:11 srv01 su[99]: pam_unix(su:session): session opened for user root by (uid=1000)
    ts = None
    parts = raw.split(None, 5)
    if len(parts) >= 4:
        ts = parse_syslog_ts(" ".join(parts[0:3]))
        host = parts[3]
    else:
        host = None

    device = host
    msg = raw
    username = None
    src_ip = None
    port = None
    event_type = EventTypes.authentication_failure
    success = False

    low = raw.lower()
    if "failed password" in low:
        m = re.search(r"for (?:invalid user )?(\S+)\s+from\s+([0-9a-fA-F:.]+)\s+port\s+(\d+)", raw)
        if m:
            username, src_ip, port = m.group(1), m.group(2), int(m.group(3))
        event_type = EventTypes.authentication_failure
        success = False
    elif "accepted password" in low or "accepted publickey" in low:
        m = re.search(r"for (\S+)\s+from\s+([0-9a-fA-F:.]+)\s+port\s+(\d+)", raw)
        if m:
            username, src_ip, port = m.group(1), m.group(2), int(m.group(3))
        event_type = EventTypes.authentication_success
        success = True
    elif "invalid user" in low:
        m = re.search(r"invalid user (\S+)\s+from\s+([0-9a-fA-F:.]+)", raw, re.IGNORECASE)
        if m:
            username, src_ip = m.group(1), m.group(2)
        event_type = EventTypes.authentication_failure
        success = False
    elif "connection closed by authenticating user" in low:
        m = re.search(r"user (\S+)\s+([0-9a-fA-F:.]+)", raw)
        if m:
            username, src_ip = m.group(1), m.group(2)
        event_type = EventTypes.authentication_failure
        success = False
    elif "sudo" in low:
        m = re.search(r"sudo:\s+(\S+)\s+:", raw)
        if m:
            username = m.group(1)
        event_type = EventTypes.privilege_escalation
        success = True
        severity = "high"
        return _pack(ts, event_type, severity, src_ip, username, device, "sudo", msg,
                     source_log_type, success=success, source_port=port)
    elif ": session opened for user" in low:
        m = re.search(r"for user (\S+)", raw)
        if m:
            username = m.group(1)
        event_type = EventTypes.authentication_success
        success = True
        return _pack(ts, event_type, "low", src_ip, username, device, "pam", msg,
                     source_log_type, success=success, source_port=port)
    elif "new session" in low and "user" in low:
        m = re.search(r"user of user (\S+)", raw)
        if m:
            username = m.group(1)
        event_type = EventTypes.authentication_success
        success = True
    else:
        # No recognizable authentication-log marker found.
        raise ParseError("Unrecognized Linux authentication log entry")

    severity = "info" if success else "medium"
    return _pack(ts, event_type, severity, src_ip, username, device, "ssh", msg,
                 source_log_type, success=success, source_port=port)


# --------------------------------------------------------------------------
# 2. Windows event logs (JSON form from wevtutil or Event Viewer export)
# --------------------------------------------------------------------------
def parse_windows(raw: str, source_log_type: str) -> dict:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Fall back to a simple "pipe"-form used by many collectors:
        # Time|Provider|EventID|Level|User|Computer|Message
        fields = [f.strip() for f in raw.split("|")]
        if len(fields) >= 5:
            ts = parse_timestamp(fields[0])
            provider, eid, level, user = fields[1], fields[2], fields[3], fields[4]
            computer = fields[5] if len(fields) > 5 else None
            msg = fields[6] if len(fields) > 6 else raw
            return _windows_pack(ts, provider, eid, level, user, computer, msg, source_log_type)
        raise ParseError("Unrecognized Windows event format")

    ts = parse_timestamp(str(data.get("TimeCreated") or data.get("timeCreated") or data.get("Timestamp")))
    provider = str(data.get("Provider") or data.get("providerName") or "")
    eid = str(data.get("EventID") or data.get("id") or data.get("eventId") or "")
    level = str(data.get("Level") or data.get("level") or "")
    user = data.get("User") or data.get("user") or data.get("SubjectUserName")
    computer = data.get("Computer") or data.get("computer") or data.get("machineName")
    msg = str(data.get("Message") or data.get("message") or data.get("EventData") or "")
    return _windows_pack(ts, provider, eid, level, str(user), str(computer), msg, source_log_type)


def _windows_pack(ts, provider, eid, level, user, computer, msg, source_log_type) -> dict:
    level = level.lower()
    severity = {"information": "info", "informational": "info", "verbose": "info",
                "warning": "low", "error": "medium", "critical": "high"}.get(level, "info")
    low = msg.lower()
    event_type = EventTypes.generic
    if "4625" in str(eid) or "failed" in low:
        event_type, severity = EventTypes.authentication_failure, "medium"
    elif "4624" in str(eid) or "logon" in low and "success" in low:
        event_type, severity = EventTypes.authentication_success, "info"
    elif "4672" in str(eid) or "special privileges" in low:
        event_type, severity = EventTypes.privilege_escalation, "high"
    elif "4688" in str(eid) or "process created" in low:
        event_type = EventTypes.process_activity
    elif "4720" in str(eid) or "user account was created" in low:
        event_type = EventTypes.account_created
    elif "4732" in str(eid) or "added to group" in low or "member added" in low:
        event_type = EventTypes.privilege_escalation
        severity = "high"
    elif "7045" in str(eid) or "service installed" in low:
        event_type = EventTypes.process_activity
    app = provider or "windows"
    return _pack(ts, event_type, severity, None, user or None, computer or None, app, msg,
                 source_log_type, success=(event_type == EventTypes.authentication_success))


# --------------------------------------------------------------------------
# 3. Web server logs (Apache / nginx combined format)
# --------------------------------------------------------------------------
WEB_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)(?: \S+)?" (?P<status>\d{3}) (?P<size>\S+)'
)
WEB_RE_REFERER = WEB_RE

def parse_web(raw: str, source_log_type: str) -> dict:
    m = WEB_RE.search(raw)
    if not m:
        raise ParseError("Unrecognized web server log format")
    ts = parse_timestamp(m.group("time"))
    ip = m.group("ip")
    path = m.group("path")
    status = int(m.group("status"))
    method = m.group("method")
    severity = "info"
    event_type = EventTypes.network_connection
    if status >= 400 and status < 500:
        event_type, severity = EventTypes.application_event, "low"
    elif status >= 500:
        event_type, severity = EventTypes.application_event, "medium"
    if any(k in path for k in ("admin", "wp-login", "login", "cgi-bin")):
        severity = "medium"
    msg = f"{method} {path} -> {status}"
    return _pack(ts, event_type, severity, ip, None, None, "webserver", msg,
                 source_log_type, destination=path, source_port=None)


# --------------------------------------------------------------------------
# 4. Firewall logs (pfSense / iptables style)
# --------------------------------------------------------------------------
def parse_firewall(raw: str, source_log_type: str) -> dict:
    low = raw.lower()
    if "blocked" in low or "deny" in low or "drop" in low:
        action = "deny"
    elif "allow" in low or "accept" in low or "pass" in low:
        action = "allow"
    else:
        action = "deny" if "block" in low else "unknown"

    src_ip = None
    dst_ip = None
    dport = None
    sport = None
    proto = None
    m = re.search(r"src[= ](\S+)", raw) or re.search(r"SRC=(\S+)", raw)
    if m:
        src_ip = norm_ip(m.group(1))
    m = re.search(r"dst[= ](\S+)", raw) or re.search(r"DST=(\S+)", raw)
    if m:
        dst_ip = norm_ip(m.group(1))
    m = re.search(r"dport[= ](\d+)", raw) or re.search(r"DPT=(\d+)", raw)
    if m:
        dport = int(m.group(1))
    m = re.search(r"sport[= ](\d+)", raw) or re.search(r"SPT=(\d+)", raw)
    if m:
        sport = int(m.group(1))
    m = re.search(r"proto[= ](\S+)", raw) or re.search(r"PROTO=(\S+)", raw)
    if m:
        proto = m.group(1)

    ts = parse_timestamp(" ".join(raw.split(None, 6)[:6])) if len(raw.split(None, 6)) >= 6 else None
    event_type = EventTypes.firewall_deny if action == "deny" else EventTypes.network_connection
    severity = "medium" if action == "deny" else "low"
    if dport in (22, 3389, 445, 1433, 3306) and action == "deny":
        severity = "high"
    msg = f"firewall {action} {proto or '?'} {src_ip or '?'} -> {dst_ip or '?'}:{dport or '?'}"
    return _pack(ts, event_type, severity, src_ip, None, None, "firewall", msg,
                 source_log_type, dst_ip=dst_ip, destination=str(dst_ip) if dst_ip else None,
                 source_port=sport, dst_port=dport)


# --------------------------------------------------------------------------
# 5. Application logs (key=value and plain text)
# --------------------------------------------------------------------------
def _parse_kv(raw: str) -> dict:
    kv: dict[str, str] = {}
    for m in re.finditer(r"(\w+)\s*=\s*\"([^\"]*)\"|(\w+)\s*=\s*(\S+)", raw):
        if m.group(1) is not None:
            kv[m.group(1)] = m.group(2)
        else:
            kv[m.group(3)] = m.group(4)
    return kv


def parse_application(raw: str, source_log_type: str) -> dict:
    # Try structured key=value
    kv = _parse_kv(raw)
    ts = None
    if "timestamp" in kv:
        ts = parse_timestamp(kv["timestamp"])
    elif "time" in kv:
        ts = parse_timestamp(kv["time"])
    else:
        m = re.match(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+\d{2}:\d{2})?)", raw)
        if m:
            ts = parse_timestamp(m.group(1))
    level = (kv.get("level") or kv.get("loglevel") or "info").lower()
    severity = {"info": "info", "debug": "info", "warn": "low", "warning": "low",
                "error": "medium", "fatal": "high", "critical": "high"}.get(level, "info")
    username = kv.get("user") or kv.get("username")
    ip = norm_ip(kv.get("ip") or kv.get("src_ip") or kv.get("client_ip"))
    app = kv.get("app") or kv.get("application") or kv.get("logger") or source_log_type
    event_type = kv.get("event_type") or kv.get("event") or EventTypes.application_event
    if event_type not in EventTypes.values():
        event_type = EventTypes.application_event
    msg = kv.get("message") or kv.get("msg") or raw
    success = kv.get("success") in ("true", "1", "yes") if "success" in kv else None
    return _pack(ts, event_type, severity, ip, username, None, app, msg,
                 source_log_type, success=success, destination=kv.get("dst_ip"))


# --------------------------------------------------------------------------
# 6. CSV security logs
# --------------------------------------------------------------------------
def parse_csv(raw: str, source_log_type: str) -> dict:
    try:
        row = next(csv.reader([raw]))
    except csv.Error as e:
        raise ParseError(f"CSV parse error: {e}")
    if len(row) < 2:
        raise ParseError("CSV row too short")
    # Try to detect a header-style mapping by field name
    named = {}
    for i, cell in enumerate(row):
        named[str(i)] = cell.strip()
    ts = parse_timestamp(named.get("0"))
    event_type = named.get("1") or EventTypes.generic
    if event_type not in EventTypes.values():
        event_type = EventTypes.generic
    severity = (named.get("2") or "info").lower()
    if severity not in Severity.values():
        severity = "info"
    username = named.get("3")
    src_ip = norm_ip(named.get("4"))
    dst_ip = norm_ip(named.get("5"))
    message = named.get("6") if len(row) > 6 else None
    return _pack(ts, event_type, severity, src_ip, username, None, None, message or raw,
                 source_log_type, dst_ip=dst_ip,
                 destination=dst_ip, success=src_ip is not None)


# --------------------------------------------------------------------------
# 7. JSON logs (generic)
# --------------------------------------------------------------------------
def parse_json(raw: str, source_log_type: str) -> dict:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"JSON parse error: {e}")
    if not isinstance(data, dict):
        raise ParseError("JSON root must be an object")

    def get(*keys, default=None):
        for k in keys:
            if k in data:
                return data[k]
        return default

    ts = parse_timestamp(str(get("timestamp", "time", "ts", "@timestamp", "datetime")))
    severity = str(get("severity", "level", "priority", default="info")).lower()
    if severity not in Severity.values():
        severity = "info"
    event_type = str(get("event_type", "event", "category", "type", default="generic"))
    if event_type not in EventTypes.values():
        event_type = EventTypes.generic
    src_ip = norm_ip(str(get("src_ip", "source_ip", "client_ip", "src")))
    dst_ip = norm_ip(str(get("dst_ip", "dest_ip", "destination_ip", "dst")))
    username = get("username", "user")
    app = get("application", "app", "service", "device")
    device = get("device", "hostname", "host")
    message = str(get("message", "msg", "event_message", "detail", default=raw))
    src_port = get("src_port", "source_port")
    dst_port = get("dst_port", "destination_port", "port")
    process = get("process", "process_name")
    return _pack(ts, event_type, severity, src_ip, str(username) if username else None,
                 str(device) if device else None, str(app) if app else None, message,
                 source_log_type, dst_ip=dst_ip,
                 destination=str(dst_ip) if dst_ip else None,
                 source_port=int(src_port) if isinstance(src_port, int) else None,
                 dst_port=int(dst_port) if isinstance(dst_port, int) else None,
                 process_name=str(process) if process else None,
                 success=get("success"))


# --------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------
class EventTypes:
    authentication_success = "authentication_success"
    authentication_failure = "authentication_failure"
    privilege_escalation = "privilege_escalation"
    process_activity = "process_activity"
    port_scan = "port_scan"
    traffic_anomaly = "traffic_anomaly"
    network_connection = "network_connection"
    config_change = "config_change"
    application_event = "application_event"
    account_created = "account_created"
    account_modified = "account_modified"
    firewall_deny = "firewall_deny"
    malware_activity = "malware_activity"
    generic = "generic"

    @classmethod
    def values(cls) -> set[str]:
        return {v for k, v in vars(cls).items() if not k.startswith("_") and isinstance(v, str)}


class Severity:
    values_set = {"info", "low", "medium", "high", "critical"}
    @classmethod
    def values(cls) -> set[str]:
        return cls.values_set


def _pack(ts, event_type, severity, src_ip, username, device, app, msg,
          source_log_type, *, dst_ip=None, destination=None, source_port=None,
          dst_port=None, success=None, process_name=None) -> dict:
    return {
        "timestamp": ts or datetime.now(timezone.utc),
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": username,
        "source": src_ip or destination or username,
        "destination": destination,
        "device": device,
        "application": app,
        "message": msg,
        "source_log_type": source_log_type,
        "source_port": source_port,
        "dst_port": dst_port,
        "success": success,
        "process_name": process_name,
    }


PARSERS = {
    "linux_auth": parse_linux_auth,
    "windows_event": parse_windows,
    "web_server": parse_web,
    "firewall": parse_firewall,
    "application": parse_application,
    "csv": parse_csv,
    "json": parse_json,
}

KNOWN_SOURCE_TYPES = set(PARSERS.keys())


def parse_log(source_log_type: str, raw: str) -> dict:
    parser = PARSERS.get(source_log_type)
    if parser is None:
        raise BadRequest(
            f"Unknown source_log_type '{source_log_type}'. Known: {sorted(KNOWN_SOURCE_TYPES)}"
        )
    return parser(raw, source_log_type)
