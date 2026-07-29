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
            },
        },
    },
]

# Tool names the model may call — used to validate dispatch.
TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


class Refused(ValueError):
    """An argument failed pre-flight validation, so no request was made."""


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
    host = value.strip().rstrip(".").lower()
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
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise Refused(f"URL scheme {parts.scheme!r} is not http or https")
    try:
        host = parts.hostname
    except ValueError as e:  # malformed authority, e.g. a bad IPv6 literal
        raise Refused(f"URL has an unparseable host: {e}") from e
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

    Never raises: a CC failure — or a refusal by `_validate_ioc` — comes back as
    a JSON `{"error": ...}` so the model records a tool_error in its evidence
    chain rather than the loop dying.
    """
    if name not in TOOL_NAMES:
        return json.dumps({"error": f"unknown tool: {name}"})
    if name == "enrich_ioc":
        try:
            _validate_ioc(arguments)
        except Refused as e:
            return json.dumps({"error": f"refused: {e}"})
    try:
        return json.dumps(cc.call(name, arguments))
    except CcError as e:
        return json.dumps({"error": str(e)})
