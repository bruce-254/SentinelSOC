"""Tests for log source parsers."""
import pytest

from app.pipeline.parsers import (
    ParseError,
    parse_application,
    parse_csv,
    parse_firewall,
    parse_json,
    parse_linux_auth,
    parse_log,
    parse_web,
    parse_windows,
)


class TestLinuxAuth:
    def test_failed_password(self):
        line = "Jun 12 10:30:45 srv01 sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2"
        r = parse_linux_auth(line, "linux_auth")
        assert r["event_type"] == "authentication_failure"
        assert r["username"] == "root"
        assert r["src_ip"] == "192.168.1.10"
        assert r["source_port"] == 22
        assert r["success"] is False

    def test_accepted_password(self):
        line = "Jun 12 10:30:46 srv01 sshd[1235]: Accepted password for alice from 10.0.0.5 port 2222 ssh2"
        r = parse_linux_auth(line, "linux_auth")
        assert r["event_type"] == "authentication_success"
        assert r["username"] == "alice"
        assert r["success"] is True

    def test_sudo_privilege(self):
        line = "Jun 12 10:31:00 srv01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
        r = parse_linux_auth(line, "linux_auth")
        assert r["event_type"] == "privilege_escalation"
        assert r["username"] == "alice"

    def test_invalid_user(self):
        line = "Jun 12 10:32:00 srv01 sshd[99]: Invalid user hacker from 8.8.8.8"
        r = parse_linux_auth(line, "linux_auth")
        assert r["event_type"] == "authentication_failure"
        assert r["username"] == "hacker"


class TestWindows:
    def test_json_failure(self):
        raw = ('{"TimeCreated": "2024-01-01T00:00:00Z", "Provider": "sec", '
               '"EventID": 4625, "Level": "Error", "User": "bob", '
               '"Computer": "host1", "Message": "An account failed to log on."}')
        r = parse_windows(raw, "windows_event")
        assert r["event_type"] == "authentication_failure"
        assert r["username"] == "bob"
        assert r["severity"] == "medium"

    def test_pipe_format(self):
        raw = "2024-01-01T00:00:00Z|Security|4624|Information|alice|host1|Logged on"
        r = parse_windows(raw, "windows_event")
        assert r["event_type"] == "authentication_success"

    def test_privilege(self):
        raw = ('{"EventID": 4672, "Level": "Information", "User": "admin", '
               '"Computer": "dc1", "Message": "Special privileges assigned to new logon."}')
        r = parse_windows(raw, "windows_event")
        assert r["event_type"] == "privilege_escalation"
        assert r["severity"] == "high"


class TestWeb:
    def test_combined_format(self):
        raw = '10.0.1.42 - - [12/Jun/2024:08:00:02 +0000] "GET /index.html HTTP/1.1" 200 5120'
        r = parse_web(raw, "web_server")
        assert r["src_ip"] == "10.0.1.42"
        assert r["severity"] == "info"

    def test_error_status(self):
        raw = '198.51.100.7 - - [12/Jun/2024:08:14:31 +0000] "GET /login HTTP/1.1" 500 512'
        r = parse_web(raw, "web_server")
        assert r["severity"] == "medium"

    def test_bad_format_raises(self):
        with pytest.raises(ParseError):
            parse_web("garbage line", "web_server")


class TestFirewall:
    def test_deny_sensitive_port(self):
        raw = "2024-06-12T08:00:11Z action=deny proto=tcp src=203.0.113.10 sport=40000 dst=10.0.0.5 dport=3389"
        r = parse_firewall(raw, "firewall")
        assert r["event_type"] == "firewall_deny"
        assert r["src_ip"] == "203.0.113.10"
        assert r["dst_ip"] == "10.0.0.5"
        assert r["dst_port"] == 3389
        assert r["severity"] == "high"


class TestApplication:
    def test_kv(self):
        raw = '2024-06-12T08:02:01Z level=error app=payments user=bob message="boom" event_type=application_event'
        r = parse_application(raw, "application")
        assert r["username"] == "bob"
        assert r["severity"] == "medium"
        assert r["application"] == "payments"


class TestCsv:
    def test_row(self):
        raw = "2024-06-12T08:00:10Z,authentication_failure,low,svc_batch,192.0.2.44,10.0.0.5,Bad creds"
        r = parse_csv(raw, "csv")
        assert r["event_type"] == "authentication_failure"
        assert r["src_ip"] == "192.0.2.44"


class TestJson:
    def test_object(self):
        raw = ('{"timestamp":"2024-06-12T08:05:00Z","event_type":"authentication_failure",'
               '"severity":"medium","src_ip":"203.0.113.10","username":"root","message":"x"}')
        r = parse_json(raw, "json")
        assert r["event_type"] == "authentication_failure"
        assert r["src_ip"] == "203.0.113.10"


def test_parse_log_dispatch_unknown_type():
    with pytest.raises(Exception):
        parse_log("nonexistent", "raw")
