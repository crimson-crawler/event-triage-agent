"""Offline tests for `enrich_ioc` pre-flight validation.

These assert the *negative* case that matters: a refused indicator must never
reach the network. Every test that expects a refusal also asserts the mock
transport was never called, so a regression that only weakens the check —
without removing it — still fails here.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from cc_agent.cc_client import CcClient
from cc_agent.tools import dispatch


class _Counter:
    """A MockTransport handler that records how many requests it saw."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, json={"ok": True})


def _ioc(value, kind):
    """Dispatch one enrich_ioc call; return (parsed_result, requests_issued)."""
    counter = _Counter()
    cc = CcClient(
        "https://cc.test/", "k", client=httpx.Client(transport=httpx.MockTransport(counter))
    )
    with cc:
        out = dispatch(cc, "enrich_ioc", {"value": value, "type": kind})
    return json.loads(out), counter.calls


def _assert_refused(value, kind):
    parsed, calls = _ioc(value, kind)
    assert "error" in parsed, f"{value!r} ({kind}) should have been refused"
    assert parsed["error"].startswith("refused:"), parsed["error"]
    assert calls == 0, f"{value!r} ({kind}) was refused but still issued {calls} request(s)"
    return parsed["error"]


def _assert_sent(value, kind):
    parsed, calls = _ioc(value, kind)
    assert parsed == {"ok": True}, parsed
    assert calls == 1, f"{value!r} ({kind}) should have been sent, saw {calls} request(s)"


# --- IP addresses ---------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "10.1.2.3",  # RFC1918 /8
        "172.16.0.1",  # RFC1918 /12
        "192.168.1.1",  # RFC1918 /16
        "127.0.0.1",  # loopback
        "169.254.169.254",  # link-local (cloud metadata)
        "100.64.0.1",  # CGNAT
        "0.0.0.0",  # unspecified
        "224.0.0.1",  # multicast
        "240.0.0.1",  # reserved
        "::1",  # IPv6 loopback
        "fe80::1",  # IPv6 link-local
        "fd00::1",  # IPv6 unique-local
    ],
)
def test_reserved_ips_are_refused_without_a_request(value):
    _assert_refused(value, "ip-dst")


@pytest.mark.parametrize(
    "value",
    [
        "203.0.113.42",  # RFC 5737 TEST-NET-3 — used by this project's own examples
        "198.51.100.5",  # RFC 5737 TEST-NET-2
        "192.0.2.1",  # RFC 5737 TEST-NET-1
        "2001:db8::1",  # RFC 3849
        "8.8.8.8",  # ordinary public address
    ],
)
def test_documentation_and_public_ips_are_sent(value):
    _assert_sent(value, "ip-dst")


def test_malformed_ip_is_refused():
    _assert_refused("not.an.ip.at.all", "ip-src")


# --- Host names -----------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "host.internal",
        "fileserver.local",
        "wiki.corp",
        "db.intranet",
        "printer.lan",
        "gw.home.arpa",
        "FIN-WS-07",  # bare hostname, no domain
        "localhost",
    ],
)
def test_internal_hostnames_are_refused_without_a_request(value):
    _assert_refused(value, "hostname")


def test_public_domain_is_sent():
    _assert_sent("evil-example-lure.com", "domain")


def test_custom_internal_suffix_is_honoured(monkeypatch):
    _assert_sent("mail.acme-widgets.com", "domain")
    monkeypatch.setenv("CC_INTERNAL_SUFFIXES", "acme-widgets.com, ad.example.org")
    _assert_refused("mail.acme-widgets.com", "domain")
    _assert_refused("dc1.ad.example.org", "domain")


def test_ip_declared_as_domain_is_refused():
    err = _assert_refused("8.8.8.8", "domain")
    assert "ip-dst" in err  # tells the model how to fix it


@pytest.mark.parametrize(
    "value",
    [
        "fileserver[.]internal",
        "dc01[.]corp",
        "internal-db01[.]local",
        "fileserver(.)internal",
        "fileserver。internal",  # U+3002 ideographic full stop
    ],
)
def test_defanged_internal_hostname_is_refused(value):
    # Defanging is the conventional way analysts write hostnames in tickets
    # and advisories — not just an evasion — so `endswith(".internal")` has
    # to see through it rather than only matching a literally dotted form.
    _assert_refused(value, "hostname")


# --- Hashes ---------------------------------------------------------------


def test_wellformed_hashes_are_sent():
    _assert_sent("d41d8cd98f00b204e9800998ecf8427e", "md5")
    _assert_sent("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1")
    _assert_sent("c" * 64, "sha256")


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("abc123", "sha256"),  # too short
        ("c" * 65, "sha256"),  # too long
        ("z" * 64, "sha256"),  # not hex
        ("d41d8cd98f00b204e9800998ecf8427e", "sha1"),  # md5 declared as sha1
    ],
)
def test_hash_shape_mismatch_is_refused(value, kind):
    _assert_refused(value, kind)


# --- URLs and email -------------------------------------------------------


def test_http_url_is_sent():
    _assert_sent("https://paypa1-account-services.top/login", "url")


@pytest.mark.parametrize(
    "value",
    [
        "file:///etc/passwd",  # non-http scheme
        "javascript:alert(1)",  # non-http scheme
        "https://",  # no host
        "http://192.168.0.5/login",  # internal IP literal
        "http://intranet.corp/portal",  # internal zone
        "http://[fe80::1]/x",  # IPv6 link-local literal
    ],
)
def test_unsafe_or_internal_urls_are_refused(value):
    _assert_refused(value, "url")


def test_public_email_is_sent():
    _assert_sent("billing@fast-invoice-delivery.icu", "email")


@pytest.mark.parametrize(
    "value",
    [
        "no-at-sign",
        "@nolocalpart.com",
        "user@",
        "helpdesk@corp.local",  # internal zone
    ],
)
def test_malformed_or_internal_email_is_refused(value):
    _assert_refused(value, "email")


# --- Argument shape -------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("8.8.8.8", "ip-address"),  # not in the enum
        ("8.8.8.8", None),  # missing
        ("", "ip-dst"),  # empty
        ("   ", "ip-dst"),  # whitespace only
        (42, "ip-dst"),  # not a string
    ],
)
def test_bad_arguments_are_refused(value, kind):
    _assert_refused(value, kind)


def test_other_tools_are_not_ioc_validated():
    """Only enrich_ioc runs the reserved-range/hostname checks in this file —
    a plain malware name still goes through. See test_tool_arguments.py for
    the argument-shape/allowlist checks that now apply to every tool."""
    counter = _Counter()
    cc = CcClient(
        "https://cc.test/", "k", client=httpx.Client(transport=httpx.MockTransport(counter))
    )
    with cc:
        out = dispatch(cc, "enrich_software", {"search": "Mimikatz"})
    assert json.loads(out) == {"ok": True}
    assert counter.calls == 1


def test_the_shipped_example_alert_still_enriches_end_to_end():
    """Guard on the README's own example.

    `examples/alert.json` carries 203.0.113.42 and a sha256. Both must survive
    validation — the documentation-range carve-out in `_check_ip` exists for
    exactly this, and a well-meant tightening that drops it would silently turn
    the flagship demo into a run with no enrichment at all.
    """
    alert = json.loads(
        (Path(__file__).resolve().parents[1] / "examples" / "alert.json").read_text()
    )
    ip = alert["evidence"][0]["ipAddress"]
    sha = alert["evidence"][1]["fileDetails"]["sha256"]

    _assert_sent(ip, "ip-dst")
    _assert_sent(sha, "sha256")

    # And the README's inline example indicator.
    _assert_sent("203.0.113.42", "ip-src")
