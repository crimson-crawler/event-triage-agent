"""Offline tests for per-tool argument sanitization (`_sanitize_arguments`).

Before this, `enrich_ioc` was the only tool with any argument validation —
`enrich_cve`, `enrich_technique`, `enrich_software`, `enrich_group`, and
`enrich_campaign` forwarded whatever dict the model produced, unchanged. These
assert the *negative* case that matters for every tool, not just `enrich_ioc`:
an unexpected property, a malformed id, or a name-shaped field carrying a
smuggled URL/email/IP must be refused before any request is made. Every
refusal test also asserts the mock transport saw zero requests.
"""

from __future__ import annotations

import json

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


def _dispatch(name, arguments):
    counter = _Counter()
    cc = CcClient(
        "https://cc.test/", "k", client=httpx.Client(transport=httpx.MockTransport(counter))
    )
    with cc:
        out = dispatch(cc, name, arguments)
    return json.loads(out), counter.calls


def _assert_refused(name, arguments):
    parsed, calls = _dispatch(name, arguments)
    assert parsed.get("error", "").startswith("refused:"), parsed
    assert calls == 0, f"{name}({arguments!r}) should have been refused, saw {calls} request(s)"
    return parsed["error"]


def _assert_sent(name, arguments):
    parsed, calls = _dispatch(name, arguments)
    assert parsed == {"ok": True}, parsed
    assert calls == 1, f"{name}({arguments!r}) should have been sent, saw {calls} request(s)"


# --- extra / unexpected properties -----------------------------------------


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("enrich_cve", {"cve_id": "CVE-2023-0001", "extra": "haxx"}),
        ("enrich_ioc", {"value": "8.8.8.8", "type": "ip-dst", "note": "internal-host.local"}),
        ("enrich_software", {"search": "Mimikatz", "unexpected": "data"}),
    ],
)
def test_unexpected_argument_is_refused_without_a_request(name, arguments):
    # An extra property is exactly how a crafted alert would try to smuggle an
    # internal hostname or a confidential field onto an otherwise-valid call.
    err = _assert_refused(name, arguments)
    assert "unexpected argument" in err


# --- id-shaped fields (cve_id, technique_id) --------------------------------


def test_valid_cve_id_is_sent():
    _assert_sent("enrich_cve", {"cve_id": "CVE-2023-12345"})


@pytest.mark.parametrize(
    "cve_id",
    [
        "not-a-cve",
        "CVE-23-0001",  # 2-digit year
        "CVE-2023-1",  # sequence too short
        "CVE-2023-0001; DROP TABLE",  # trailing junk appended to a valid id
    ],
)
def test_malformed_cve_id_is_refused(cve_id):
    _assert_refused("enrich_cve", {"cve_id": cve_id})


def test_missing_required_cve_id_is_refused():
    _assert_refused("enrich_cve", {})


def test_valid_technique_id_is_sent():
    _assert_sent("enrich_technique", {"technique_id": "T1566.001"})
    _assert_sent("enrich_technique", {"technique_id": "T1490"})


@pytest.mark.parametrize("technique_id", ["1566", "TT1566", "T156", "T1566.abcd"])
def test_malformed_technique_id_is_refused(technique_id):
    _assert_refused("enrich_technique", {"technique_id": technique_id})


# --- free-text name fields (search) -----------------------------------------


def test_plain_names_are_sent():
    _assert_sent("enrich_software", {"search": "Cobalt Strike"})
    _assert_sent("enrich_group", {"search": "FIN7"})
    _assert_sent("enrich_campaign", {"search": "Operation Aurora"})


@pytest.mark.parametrize(
    "value",
    [
        "http://fileserver.internal/creds.txt",  # a URL, not a name
        "helpdesk@corp.local",  # email-shaped
        "10.1.2.3",  # a bare IP
        "x" * 201,  # over the length cap
        # A bare internal hostname, no scheme, no "@" — the shape that
        # previously slipped through the URL/email/IP-only checks.
        "fileserver.internal",
        "dc01.corp",
        "hr-payroll.ad.acme.example",  # a CC_INTERNAL_SUFFIXES-style zone
        "ProjectApollo internal-db01.local",  # hostname embedded in prose
    ],
)
def test_name_field_carrying_smuggled_data_is_refused(value):
    # A malware/actor/campaign name has no legitimate reason to look like a
    # URL, an address, an internal hostname, or run past a reasonable length —
    # those are signs of data being smuggled through a free-text field, not
    # an actual name.
    _assert_refused("enrich_software", {"search": value})


def test_name_field_internal_hostname_honours_custom_suffix(monkeypatch):
    monkeypatch.setenv("CC_INTERNAL_SUFFIXES", "acme-widgets.com")
    _assert_refused("enrich_software", {"search": "seen talking to mail.acme-widgets.com"})


@pytest.mark.parametrize(
    "value",
    [
        # An internal hostname immediately followed by a delimiter the old
        # tokenizer didn't split on ("host:port", "host/path") kept it glued
        # to the trailing text, so `token.endswith(suffix)` never matched.
        "beaconing to internal-db01.local:445",
        "saw traffic to fileserver.internal/share",
        # A reserved IP embedded in prose — the whole-string check only
        # caught a value that was *nothing but* an IP.
        "Cobalt Strike beacon observed from 10.0.0.5 pivoting to 172.16.4.9",
        "link-local fe80::1 beacon",  # IPv6; no "." at all
        "unique-local fd00::1 seen",  # IPv6 RFC4193
        "pivoted through 10.0.0.5:8080 to reach the db",  # IPv4 with a port
    ],
)
def test_name_field_carrying_embedded_address_with_trailing_punctuation_is_refused(value):
    _assert_refused("enrich_software", {"search": value})


@pytest.mark.parametrize(
    "value",
    [
        "seen at 8.8.8.8 the same day",  # a public IP mentioned in prose
        "C2 observed at 203.0.113.5",  # RFC 5737 documentation range
        "reached out to cdn.example.org:443 for updates",  # public host:port
    ],
)
def test_name_field_mentioning_a_public_address_is_sent(value):
    # The tokenized IP/hostname check reuses `_check_ip`'s reserved-range
    # logic specifically so a public indicator mentioned in descriptive text
    # isn't refused — only internal/reserved addresses are a leak.
    _assert_sent("enrich_software", {"search": value})


@pytest.mark.parametrize(
    "value",
    [
        # Defanged notation is how hostnames are conventionally written in
        # ticket text and vendor advisories (to avoid auto-linking), not a
        # contrived evasion — so it's a form an internal name is likely to
        # arrive in during ordinary use, not just a deliberate attack.
        "fileserver[.]internal",
        "fileserver(.)internal",
        "fileserver{dot}internal",
        "fileserver。internal",  # U+3002 ideographic full stop
        "fileserver．internal",  # U+FF0E fullwidth full stop
        "dc01[.]corp",
    ],
)
def test_name_field_carrying_defanged_internal_hostname_is_refused(value):
    _assert_refused("enrich_software", {"search": value})


@pytest.mark.parametrize(
    "value",
    [
        "AKIAIOSFODNN7EXAMPLE",  # AWS access key id
        "password: SuperSecret123!",  # the exact prose shape from the audit
        "api_key=sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
        "ghp_" + "a" * 40,  # GitHub token
        "xoxb-" + "a" * 20,  # Slack token
        # The jwt.io homepage's own example token, not a real secret — but
        # it's still JWT-shaped, so gitleaks' generic `jwt` rule flags it
        # like any other; the inline comment below is gitleaks' documented
        # per-line suppression, not a lint no-op.
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."  # gitleaks:allow
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "-----BEGIN RSA PRIVATE KEY-----",
    ],
)
def test_name_field_carrying_a_credential_is_refused(value):
    # The third smuggling vector named in the audit alongside URLs/hostnames:
    # "a credential found in the alert ... into enrich_software.search".
    _assert_refused("enrich_software", {"search": value})


@pytest.mark.parametrize(
    "value",
    [
        "Password Stealer",  # a real malware family name — no ": <value>" shape
        "TokenStealer",  # "token" substring with no word boundary / delimiter
        "APT29",
    ],
)
def test_name_field_resembling_but_not_matching_a_credential_is_sent(value):
    # The credential check is shape-based specifically so legitimate names
    # that merely contain a sensitive-sounding word don't get refused.
    _assert_sent("enrich_group", {"search": value})


# --- resolved-id fields (2nd call of the two-step lookups) ------------------


def test_resolved_id_is_sent():
    _assert_sent("enrich_software", {"software_id": "abc123"})
    _assert_sent("enrich_group", {"group_id": "abc123"})
    _assert_sent("enrich_campaign", {"campaign_id": "abc123"})


def test_oversized_id_is_refused():
    _assert_refused("enrich_software", {"software_id": "x" * 200})


def test_id_field_carrying_smuggled_data_is_refused():
    # software_id/group_id/campaign_id are meant to be an id CC's own search
    # handed back, not free text — they get the same smuggled-address check
    # as `search`.
    _assert_refused("enrich_software", {"software_id": "fileserver.internal"})
    _assert_refused("enrich_group", {"group_id": "10.1.2.3"})


# --- include -----------------------------------------------------------------


def test_include_details_is_sent():
    _assert_sent("enrich_cve", {"cve_id": "CVE-2023-0001", "include": ["details"]})


def test_other_shaped_section_names_are_also_sent():
    # system_prompt.md tells the model it may "expand the include list in a
    # follow-up call if the verdict genuinely needs the cross-reference" —
    # this project doesn't enumerate CC's full section vocabulary, so a
    # short lowercase token other than "details" must still go through.
    _assert_sent("enrich_cve", {"cve_id": "CVE-2023-0001", "include": ["relationships"]})


@pytest.mark.parametrize(
    "include",
    [
        "details",  # a string, not a list
        [1, 2],  # a list, but not of strings
        ["DETAILS"],  # uppercase — not the shape of a real section name
        ["not a section"],  # contains whitespace
        [""],  # empty
        ["x" * 40],  # over the length cap
    ],
)
def test_invalid_include_is_refused(include):
    _assert_refused("enrich_cve", {"cve_id": "CVE-2023-0001", "include": include})


# --- basic type/shape --------------------------------------------------------


def test_non_string_field_is_refused():
    _assert_refused("enrich_cve", {"cve_id": 12345})


def test_whitespace_only_field_is_refused():
    _assert_refused("enrich_cve", {"cve_id": "   "})


# --- argument-spec parity (dispatch must never raise) -----------------------


def test_arg_specs_cover_every_declared_tool():
    from cc_agent.tools import _ARG_SPECS, TOOL_NAMES

    assert set(_ARG_SPECS) == TOOL_NAMES


def test_sanitize_arguments_refuses_rather_than_raises_for_an_unknown_tool():
    from cc_agent.tools import Refused, _sanitize_arguments

    # `dispatch()` already turns an unknown name into a clean error before
    # reaching `_sanitize_arguments`, but the function itself must not raise
    # KeyError if that guard is ever bypassed or a tool is added to TOOLS
    # without a matching _ARG_SPECS entry.
    with pytest.raises(Refused):
        _sanitize_arguments("not_a_real_tool", {})


# --- malformed URLs must refuse cleanly, not crash --------------------------


def test_malformed_enrich_ioc_url_is_refused_not_a_crash():
    # urlsplit() itself raises ValueError on an unmatched IPv6 bracket — not
    # just `.hostname` access — so it has to be inside the same try as the
    # call that can raise it, or this crashes the agent loop instead of
    # returning a clean tool_error.
    _assert_refused("enrich_ioc", {"value": "http://[::1", "type": "url"})
