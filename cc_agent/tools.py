"""The six CC endpoints as OpenAI function-calling tool schemas.

The single source of truth for the agent's tools. `dispatch()` maps a model
tool call → `CcClient` → JSON result string.

`dispatch()` also enforces the IOC rules that `system_prompt.md` states, rather
than only asking the model to follow them. See `_validate_ioc`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any
from urllib.parse import urlsplit

from .cc_client import CcClient, CcError

# IOC types the model may declare. Referenced by the tool schema below and by
# the validator, so the two can never drift apart.
IOC_TYPES = (
    "ip-dst",
    "ip-src",
    "domain",
    "hostname",
    "md5",
    "sha1",
    "sha256",
    "url",
    "email",
)

_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX = re.compile(r"[0-9a-fA-F]+")
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,19}", re.IGNORECASE)
_TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?", re.IGNORECASE)

# CGNAT — `ipaddress` exposes no flag for it.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

# RFC 5737 / RFC 3849 documentation ranges. Python reports these as
# `is_private`, but they are globally reserved for examples and disclose nothing
# about anyone's network — and they are what this project's own README and
# examples use. Allow them through; CC will simply have no intel to return.
_DOC_RANGES = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

# Suffixes that identify internal or non-routable name space. Site-specific
# zones can be added via CC_INTERNAL_SUFFIXES (comma-separated).
_INTERNAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".home.arpa",
    ".corp",
    ".home",
    ".private",
    ".test",
    ".example",
    ".invalid",
)

_INCLUDE = {
    "type": "array",
    "items": {"type": "string"},
    "description": "Response sections to include. Pass ['details'] first — the "
    "default (omitted) can return 100+ KB on popular entities.",
}

# OpenAI tool schemas. Descriptions carry the 'call this WHEN' rule so the
# model uses them the way the system prompt intends.
TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "enrich_cve",
            "description": "Enrich a single CVE (EPSS, KEV, CWE, linked ATT&CK "
            "techniques, actors, mitigations). Call once per CVE-YYYY-NNNN id.",
            "parameters": {
                "type": "object",
                "required": ["cve_id"],
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE-YYYY-NNNN"},
                    "include": _INCLUDE,
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_technique",
            "description": "Enrich a MITRE ATT&CK technique (T#### / T####.###). "
            "Call once per technique id. Pass include=['details'].",
            "parameters": {
                "type": "object",
                "required": ["technique_id"],
                "properties": {
                    "technique_id": {"type": "string", "description": "T#### or T####.###"},
                    "include": _INCLUDE,
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_ioc",
            "description": "Enrich an IOC (hash/IP/domain/URL/email/hostname) with "
            "MISP hits, linked actors/malware, exploitability. Call once per IOC. "
            "Reserved IPs (RFC1918, loopback, link-local, CGNAT), bare hostnames "
            "and internal zones (.local, .internal, .corp) are refused before "
            "sending; `type` must match the shape of `value`.",
            "parameters": {
                "type": "object",
                "required": ["value", "type"],
                "properties": {
                    "value": {"type": "string", "description": "The indicator value."},
                    "type": {
                        "type": "string",
                        "enum": list(IOC_TYPES),
                        "description": "IOC type — must match value's shape.",
                    },
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_software",
            "description": "Enrich a malware/tool name (from threatFamilyName etc.). "
            "Two-step: call with search='<name>'; if it returns a stub "
            "(search_results[0] with empty techniques), re-call with "
            "software_id from that result. Pass include=['details'].",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Malware/tool name."},
                    "software_id": {"type": "string", "description": "Resolved id (2nd call)."},
                    "include": _INCLUDE,
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_group",
            "description": "Enrich a threat-actor/group name (from actorDisplayName). "
            "Two-step like enrich_software: search='<name>' then group_id. "
            "Pass include=['details'].",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Actor/group name."},
                    "group_id": {"type": "string", "description": "Resolved id (2nd call)."},
                    "include": _INCLUDE,
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_campaign",
            "description": "Enrich a named campaign. Two-step like enrich_software: "
            "search='<name>' then campaign_id. Pass include=['details'].",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Campaign name."},
                    "campaign_id": {"type": "string", "description": "Resolved id (2nd call)."},
                    "include": _INCLUDE,
                },
                "additionalProperties": False,
            },
        },
    },
]

# Tool names the model may call — used to validate dispatch.
TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


class Refused(ValueError):
    """An argument failed pre-flight validation, so no request was made."""


_MAX_ID_LEN = 128
_MAX_NAME_LEN = 200
# CC's `include` values are response-section names this project doesn't fully
# enumerate (only "details" is documented) — system_prompt.md explicitly tells
# the model it may "expand the include list in a follow-up call if the verdict
# genuinely needs the cross-reference", so hard-coding a single accepted value
# would refuse exactly the behavior the prompt asks for. Validate shape
# instead of an exact set: a short lowercase token, the way a real section
# name would look, not free text.
_INCLUDE_TOKEN = re.compile(r"[a-z][a-z_]{0,31}")

# Per-tool argument allowlist: field name -> (required, kind). Used to rebuild
# the outbound body from only known-good fields.
#
# Before this, only `enrich_ioc` was validated — every other tool forwarded
# whatever dict the model produced, verbatim, with no check for extra
# properties or free text placed in a field nothing here inspects. A crafted
# alert could steer a susceptible model into putting an internal hostname or a
# confidential field into `enrich_software.search`, or onto an extra property
# tacked onto an otherwise-valid `enrich_ioc` call, and it would reach the
# third-party CC endpoint unchanged. Every tool now goes through the same
# allowlist: an undeclared key is refused rather than silently forwarded.
_ARG_SPECS: dict[str, dict[str, tuple[bool, str]]] = {
    "enrich_cve": {
        "cve_id": (True, "cve_id"),
        "include": (False, "include"),
    },
    "enrich_technique": {
        "technique_id": (True, "technique_id"),
        "include": (False, "include"),
    },
    "enrich_ioc": {
        "value": (True, "plain"),
        "type": (True, "plain"),
    },
    "enrich_software": {
        "search": (False, "name"),
        "software_id": (False, "id"),
        "include": (False, "include"),
    },
    "enrich_group": {
        "search": (False, "name"),
        "group_id": (False, "id"),
        "include": (False, "include"),
    },
    "enrich_campaign": {
        "search": (False, "name"),
        "campaign_id": (False, "id"),
        "include": (False, "include"),
    },
}

# A tool added to TOOLS without a matching entry here would make
# `_sanitize_arguments`'s `_ARG_SPECS[name]` raise `KeyError` for a valid tool
# name, killing the agent loop despite `dispatch()`'s docstring promising it
# never raises. Catch that at import time instead of at whatever point in
# production someone happens to hit it.
assert set(_ARG_SPECS) == TOOL_NAMES, (
    f"_ARG_SPECS is out of sync with TOOLS: {set(_ARG_SPECS) ^ TOOL_NAMES}"
)


# Split on any run of characters that can't appear in a hostname/IP literal
# (letters, digits, '.', '-', ':') — not just whitespace/comma/parens.
# Splitting too narrowly let a delimiter the model chose ("/", a quote —
# "saw traffic to fileserver.internal/share") keep an internal hostname glued
# to trailing text, so `token.endswith(suffix)` never matched even though the
# hostname was plainly present. ':' has to stay IN the keep-set (not a
# delimiter): it's the address separator inside an IPv6 literal ("fe80::1"),
# so splitting on it would mangle one into unparseable fragments. A trailing
# ":<port>" on a host/IPv4 token is handled separately, by stripping it before
# the hostname/IP re-check below.
_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9.\-:]+")
_TRAILING_PORT = re.compile(r":\d{1,5}$")

# Recognizable secret shapes, the same category gitleaks already scans for at
# publish time (see ci/publish-public.sh). Deliberately shape-based, not a
# generic entropy check: a malware/actor/campaign name can itself be an
# arbitrary-looking alphanumeric string, so flagging "looks random" would
# false-positive on legitimate names. These patterns don't have that problem —
# nothing in a real name looks like an AWS key, a GitHub token, a JWT, a PEM
# header, or "password: <value>".
_CREDENTIAL_PATTERNS = (
    re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA|ABIA)[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),  # GitHub token
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack token
    re.compile(r"sk-(?:ant-)?[A-Za-z0-9_-]{20,}"),  # OpenAI/Anthropic-style API key
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    # "password: <value>" / "api_key=<value>" — the shape of a leaked secret
    # pasted from an alert, not of a name. Requires the `: ` / `=` delimiter
    # so a malware family literally named e.g. "Password Stealer" (no
    # delimiter, no value) doesn't trip it.
    re.compile(
        r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|credential)s?"
        r"\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
)

# Defanged notation ("fileserver[.]internal", "dc01(.)corp", a full-width or
# ideographic full stop) is how hostnames and IPs are conventionally written
# in ticket text and vendor advisories — to keep them from auto-linking or
# being clicked — so it's the form an internal name is most likely to arrive
# in during normal use, not a contrived evasion. Fold it back to a plain '.'
# before any check runs; otherwise `endswith(".internal")` (or parsing an
# address a piece at a time) never matches and the name goes out verbatim.
# This is a shape-based normalization, not a defense against a determined
# injection: spacing it out, spelling out "dot" with extra words, base64,
# hyphenation, or splitting the value across turns all still get through, and
# no filter of this kind closes that — see README.md/SECURITY.md for what
# this control does and doesn't guarantee.
_DEFANGED_DOT = re.compile(r"\s*(?:[\[({<]\s*(?:\.|dot)\s*[\])}>]|[。．｡])\s*", re.IGNORECASE)


def _undefang(value: str) -> str:
    return _DEFANGED_DOT.sub(".", value)


def _refuse_if_reserved_ip(field: str, token: str) -> bool:
    """If `token` parses as an IP address, refuse it via `_check_ip`'s
    reserved-range logic (raises `Refused`) and return True. Returns False
    if `token` isn't an IP at all — including a public/doc-range one, which
    `_check_ip` itself lets through, since a public IP mentioned in prose
    isn't a network-topology leak.
    """
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    try:
        _check_ip(token)
    except Refused:
        raise Refused(
            f"'{field}' contains a reserved/internal IP address ({token!r}) — refused"
        ) from None
    return True


def _reject_smuggled_address(field: str, value: str) -> None:
    """Refuse free text carrying an address or a credential rather than an
    actual name.

    A malware/actor/campaign name, or a resolved id, has no legitimate reason
    to contain a URL, an email/user@host shape, a bare IP literal, an internal
    hostname or reserved IP, or a recognizable secret — those are signs of
    data being smuggled through a field that otherwise accepts arbitrary text
    (the whole point of a name-search lookup). The value is tokenized for the
    hostname/IP checks rather than checked whole, so an address embedded
    alongside other words ("beaconing to internal-db01.local:445", "beacon
    observed from fe80::1") is still caught, not just a value that is
    nothing but the address. A *public* IP mentioned in prose ("seen at
    8.8.8.8") is not refused here — that's descriptive text about a public
    indicator, not a network-topology leak; `_check_ip`'s reserved-range logic
    is reused so only the internal ranges `enrich_ioc` itself refuses trip
    this too. Defanged notation ("internal-db01[.]local") is folded back to a
    plain '.' before any of the above, so it doesn't dodge them.
    """
    value = _undefang(value)
    if "://" in value or "@" in value:
        raise Refused(f"'{field}' looks like a URL or address, not a name — refused")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise Refused(f"'{field}' is an IP address, not a name — refused")
    for pattern in _CREDENTIAL_PATTERNS:
        match = pattern.search(value)
        if match:
            raise Refused(f"'{field}' appears to contain a credential — refused")
    for raw_token in _TOKEN_SPLIT.split(value):
        token = raw_token.strip(".")
        if not token:
            continue
        if _refuse_if_reserved_ip(field, token):
            continue
        # Not a bare IP literal — try it as "host:port" / "ip:port" by
        # stripping a trailing port. A genuine IPv6 literal ("fe80::1") was
        # already handled above without stripping anything, since ':' is
        # kept in the token rather than split on.
        host_part = _TRAILING_PORT.sub("", token).strip(".").lower()
        if host_part != token.lower():
            _refuse_if_reserved_ip(field, host_part)
        if "." in host_part and any(host_part.endswith(s) for s in _internal_suffixes()):
            raise Refused(f"'{field}' contains an internal hostname ({host_part!r}) — refused")


def _checked(field: str, kind: str, value: Any) -> Any:
    """Validate one field's value against its declared `kind`. Raises `Refused`."""
    if kind == "include":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise Refused(f"'{field}' must be a list of strings")
        bad = [v for v in value if not _INCLUDE_TOKEN.fullmatch(v)]
        if bad:
            raise Refused(f"'{field}' contains invalid section name(s): {bad!r}")
        return value

    if not isinstance(value, str):
        raise Refused(f"'{field}' must be a string")
    value = value.strip()
    if not value:
        raise Refused(f"'{field}' must be a non-empty string")

    if kind == "cve_id":
        if len(value) > 40 or not _CVE_ID.fullmatch(value):
            raise Refused(f"'{field}' does not look like CVE-YYYY-NNNN: {value[:40]!r}")
    elif kind == "technique_id":
        if len(value) > 20 or not _TECHNIQUE_ID.fullmatch(value):
            raise Refused(f"'{field}' does not look like T#### or T####.###: {value[:20]!r}")
    elif kind == "id":
        if len(value) > _MAX_ID_LEN:
            raise Refused(f"'{field}' is over {_MAX_ID_LEN} characters")
        _reject_smuggled_address(field, value)
    elif kind == "name":
        if len(value) > _MAX_NAME_LEN:
            raise Refused(f"'{field}' is over {_MAX_NAME_LEN} characters")
        _reject_smuggled_address(field, value)
    # kind == "plain" (enrich_ioc's value/type): no shape check here — they
    # get their own dedicated validation in `_validate_ioc` right after.
    return value


def _sanitize_arguments(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Rebuild `arguments` using only the fields `name`'s spec declares.

    Raises `Refused` on an unexpected key, a missing required key, or a value
    that fails its field's check — before any request is built. Never raises
    `KeyError`: the module-level assert above should make a missing spec
    entry impossible, but `dispatch()`'s "never raises" contract shouldn't
    depend on that holding.
    """
    spec = _ARG_SPECS.get(name)
    if spec is None:
        raise Refused(f"no argument spec registered for tool {name!r}")
    unknown = set(arguments) - set(spec)
    if unknown:
        raise Refused(f"unexpected argument(s): {', '.join(sorted(unknown))}")

    clean: dict[str, Any] = {}
    for field, (required, kind) in spec.items():
        if field not in arguments:
            if required:
                raise Refused(f"missing required argument '{field}'")
            continue
        clean[field] = _checked(field, kind, arguments[field])
    return clean


def _internal_suffixes() -> tuple[str, ...]:
    extra = os.environ.get("CC_INTERNAL_SUFFIXES", "")
    custom = tuple(
        "." + s.strip().lstrip(".").lower() for s in extra.split(",") if s.strip().strip(".")
    )
    return _INTERNAL_SUFFIXES + custom


def _check_ip(value: str) -> None:
    """Reject any address that describes someone's internal network."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as e:
        raise Refused(f"{value!r} is not a valid IP address") from e

    if any(ip in net for net in _DOC_RANGES):
        return  # documentation range — carries no site information

    for flag, why in (
        ("is_private", "a private address (RFC1918 / RFC4193)"),
        ("is_loopback", "loopback"),
        ("is_link_local", "link-local"),
        ("is_reserved", "reserved"),
        ("is_multicast", "multicast"),
        ("is_unspecified", "the unspecified address"),
    ):
        if getattr(ip, flag):
            raise Refused(f"{value} is {why} — not sent to CC")
    if ip.version == 4 and ip in _CGNAT:
        raise Refused(f"{value} is CGNAT (100.64.0.0/10) — not sent to CC")


def _check_hostname(value: str) -> None:
    # Defanged notation ("dc01[.]corp") is folded back to '.' for the check
    # below — see `_undefang` — so it doesn't dodge the internal-zone refusal
    # just because it isn't a literally dotted hostname.
    host = _undefang(value).strip().rstrip(".").lower()
    if not host:
        raise Refused("hostname is empty")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise Refused(f"{value!r} is an IP address — use type 'ip-dst' or 'ip-src'")
    if "." not in host:
        raise Refused(
            f"{value!r} is a bare hostname with no domain — likely internal, not sent to CC"
        )
    for suffix in _internal_suffixes():
        if host.endswith(suffix):
            raise Refused(f"{value!r} is in the internal/reserved zone '{suffix}' — not sent to CC")


def _check_host_or_ip(value: str) -> None:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        _check_hostname(value)
    else:
        _check_ip(value.strip("[]"))


def _check_hash(value: str, kind: str) -> None:
    want = _HASH_LENGTHS[kind]
    if len(value) != want or not _HEX.fullmatch(value):
        raise Refused(f"{value[:16]!r} is not a {want}-character hex {kind}")


def _check_url(value: str) -> None:
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError as e:
        # `urlsplit()` itself raises on a malformed authority (e.g. an
        # unmatched IPv6 bracket, "http://[::1") — not just `.hostname`
        # access — so both have to be inside the same try.
        raise Refused(f"URL is malformed: {e}") from e
    if parts.scheme not in ("http", "https"):
        raise Refused(f"URL scheme {parts.scheme!r} is not http or https")
    if not host:
        raise Refused("URL has no host")
    _check_host_or_ip(host)


def _check_email(value: str) -> None:
    local, sep, domain = value.rpartition("@")
    if not sep or not local or not domain:
        raise Refused(f"{value!r} is not an email address")
    _check_host_or_ip(domain)


def _validate_ioc(arguments: dict[str, Any]) -> None:
    """Enforce the `enrich_ioc` rules that system_prompt.md states.

    Every argument here originates from a model reasoning over attacker-reachable
    text, and is about to be POSTed to a third-party API. Leaving the
    reserved-range rule in the prompt alone meant a crafted observation could
    walk internal hostnames and RFC1918 addresses out of the perimeter one
    lookup at a time. Checking the value shape as well stops a mismatched
    `type` from silently producing a useless paid request.

    Raises `Refused` before any request is made.
    """
    value = arguments.get("value")
    kind = arguments.get("type")
    if not isinstance(value, str) or not value.strip():
        raise Refused("'value' must be a non-empty string")
    if kind not in IOC_TYPES:
        raise Refused(f"'type' must be one of {', '.join(IOC_TYPES)}")

    value = value.strip()
    if kind in ("ip-dst", "ip-src"):
        _check_ip(value)
    elif kind in ("domain", "hostname"):
        _check_hostname(value)
    elif kind in _HASH_LENGTHS:
        _check_hash(value, kind)
    elif kind == "url":
        _check_url(value)
    elif kind == "email":
        _check_email(value)


def dispatch(cc: CcClient, name: str, arguments: dict[str, Any]) -> str:
    """Run one CC tool call and return a JSON string for the model.

    Never raises: a CC failure, or a refusal by `_sanitize_arguments` /
    `_validate_ioc`, comes back as a JSON `{"error": ...}` so the model
    records a tool_error in its evidence chain rather than the loop dying.
    """
    if name not in TOOL_NAMES:
        return json.dumps({"error": f"unknown tool: {name}"})
    try:
        arguments = _sanitize_arguments(name, arguments)
    except Refused as e:
        return json.dumps({"error": f"refused: {e}"})
    if name == "enrich_ioc":
        try:
            _validate_ioc(arguments)
        except Refused as e:
            return json.dumps({"error": f"refused: {e}"})
    try:
        return json.dumps(cc.call(name, arguments))
    except CcError as e:
        return json.dumps({"error": str(e)})
