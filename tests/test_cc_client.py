"""Offline tests — CC client + tool dispatch via httpx.MockTransport.

No network, no keys, no OpenAI/Azure. Run: `pytest` (needs the [dev] extra).
"""

from __future__ import annotations

import json

import httpx

from cc_agent.cc_client import CcClient, CcError
from cc_agent.tools import TOOL_NAMES, dispatch


def _cc(handler) -> CcClient:
    return CcClient(
        "https://cc.test/", "k", client=httpx.Client(transport=httpx.MockTransport(handler))
    )


def test_call_hits_right_path_with_api_key():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["path"] = req.url.path
        seen["key"] = req.headers.get("X-API-Key")
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"cve_id": "CVE-2023-21529", "kev": {"in_kev": True}})

    with _cc(handler) as cc:
        out = cc.call("enrich_cve", {"cve_id": "CVE-2023-21529"})

    assert seen["path"] == "/v1/enrich/cve"
    assert seen["key"] == "k"
    assert seen["body"] == {"cve_id": "CVE-2023-21529"}
    assert out["kev"]["in_kev"] is True


def test_unknown_operation_raises():
    with _cc(lambda r: httpx.Response(200, json={})) as cc:
        try:
            cc.call("enrich_nope", {})
            raise AssertionError("expected CcError")
        except CcError:
            pass


def test_dispatch_returns_json_error_on_failure_never_raises():
    # A 404 must degrade to a JSON error string so the agent loop keeps going.
    with _cc(lambda r: httpx.Response(404)) as cc:
        out = dispatch(cc, "enrich_ioc", {"value": "203.0.113.42", "type": "ip-dst"})
    parsed = json.loads(out)
    assert "error" in parsed


def test_dispatch_unknown_tool_is_json_error():
    with _cc(lambda r: httpx.Response(200, json={})) as cc:
        assert "error" in json.loads(dispatch(cc, "enrich_bogus", {}))


def test_all_six_tools_present():
    assert {
        "enrich_cve",
        "enrich_technique",
        "enrich_ioc",
        "enrich_software",
        "enrich_group",
        "enrich_campaign",
    } == TOOL_NAMES
