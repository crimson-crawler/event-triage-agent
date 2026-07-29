"""Minimal Crimson Crawler (CC) API client.

A narrow, dependency-light wrapper over CC's `/v1/enrich/*` endpoints. All
endpoints are POST + `X-API-Key` auth. Each method returns the parsed JSON
body as a plain dict (the agent feeds it straight back to the model), or
raises `CcError` on any failure so the agent can record a tool error instead
of crashing.

This is intentionally self-contained (no shared platform code) so the repo can
be lifted out and open-sourced on its own.
"""

from __future__ import annotations

from typing import Any

import httpx

# The six enrichment endpoints, keyed by the tool/operation name the agent
# calls. Kept in one place so the client and the tool layer agree.
ENDPOINTS = {
    "enrich_cve": "/v1/enrich/cve",
    "enrich_technique": "/v1/enrich/technique",
    "enrich_ioc": "/v1/enrich/ioc",
    "enrich_software": "/v1/enrich/software",
    "enrich_group": "/v1/enrich/group",
    "enrich_campaign": "/v1/enrich/campaign",
}


class CcError(RuntimeError):
    """A CC request failed (HTTP error, non-2xx, or unparseable body)."""


class CcClient:
    """Synchronous CC client. Holds one `httpx.Client` and reuses it.

    Pass `client` to inject a transport (tests use `httpx.MockTransport`);
    otherwise one is built from `base_url` + `api_key`.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    def __enter__(self) -> CcClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def call(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch one enrichment call by operation name (e.g. 'enrich_cve').

        `arguments` is the request body the model produced. Returns the parsed
        JSON dict; raises `CcError` on any failure (HTTP, non-2xx, bad JSON).
        """
        path = ENDPOINTS.get(operation)
        if path is None:
            raise CcError(f"unknown CC operation: {operation!r}")
        url = f"{self.base_url}{path}"
        headers = {"X-API-Key": self._api_key, "Content-Type": "application/json"}
        try:
            resp = self._client.post(url, headers=headers, json=arguments)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise CcError(f"{operation} → HTTP {e.response.status_code} for {arguments}") from e
        except (httpx.HTTPError, ValueError) as e:
            raise CcError(f"{operation} failed for {arguments}: {e}") from e
