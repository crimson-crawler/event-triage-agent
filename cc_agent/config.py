"""Environment-driven config. Loads a local `.env` if present (via
python-dotenv), then reads settings from the environment. No secrets in code.
"""

from __future__ import annotations

import ipaddress
import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


def _load_dotenv() -> None:
    """Load `.env` if python-dotenv is installed — only from `CC_DOTENV` (an
    explicit, operator-named path) or exactly `./.env`. No upward search.

    This used to walk from the invocation directory up through every parent
    (`find_dotenv(usecwd=True)`) and load the first `.env` it found, warning
    only if that file lived outside the current directory. That is not enough:
    anyone who can place a file above wherever an operator happens to run
    `cc-agent` — a shared build server, a checkout of someone else's project —
    can point OPENAI_BASE_URL or CRIMSON_CRAWLER_BASE_URL at an endpoint of
    their choosing, and the first request hands it the real API key. Real
    environment variables still win over anything `.env` sets, but the fix is
    to not load the untrusted file in the first place, not to load it louder.

    `./.env` reached through a symlink pointing outside the current directory
    tree is refused the same way — it is an ancestor file wearing a local
    name. A symlink pointing *inside* the current directory (e.g. `.env ->
    config/prod.env`) is loaded: anything already writable inside the project
    tree is already trusted.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:  # optional convenience — real env vars work regardless
        return

    explicit = os.environ.get("CC_DOTENV")
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            print(f"cc-agent: CC_DOTENV={str(path)!r} does not exist.", file=sys.stderr)
            return
    else:
        path = Path.cwd() / ".env"
        if not path.is_file():
            return
        try:
            resolved = path.resolve()
            here = Path.cwd().resolve()
        except OSError:
            resolved = here = None
        # Containment, not exact-parent equality: a symlink to a file in a
        # *subdirectory* of cwd (`.env -> config/prod.env`) is still inside
        # the tree the operator already controls, not an ancestor escape.
        if resolved is None or not resolved.is_relative_to(here):
            print(
                "cc-agent: ./.env is a symlink pointing outside the current directory — "
                "not loaded. Set CC_DOTENV to load it explicitly if that's intentional.",
                file=sys.stderr,
            )
            return

    try:
        load_dotenv(path)
    except (OSError, UnicodeDecodeError, ValueError) as e:
        # A malformed or unreadable .env used to disappear into a blanket
        # `except Exception: pass`, leaving the user with a bare "KEY is not
        # set" and no hint that the file they wrote had failed to parse.
        print(f"cc-agent: could not read {path}: {e}", file=sys.stderr)


_load_dotenv()


class ConfigError(RuntimeError):
    """A required setting is missing."""


def _require(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise ConfigError(
            f"{name} is not set. Copy .env.example to .env and fill it in (or export {name})."
        )
    return v


def _positive_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as e:
        raise ConfigError(f"{name} must be a number, got {raw!r}.") from e
    # `nan <= 0` is False and `inf > 0` is True, so both pass a bare `<= 0`
    # check and would reach the client as a non-positive or unbounded timeout —
    # the exact hang this setting exists to prevent.
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{name} must be a finite number greater than 0, got {value}.")
    return value


def _is_loopback(host: str) -> bool:
    host = host.strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validated_base_url(name: str, url: str, *, allow_insecure_env: str) -> str:
    """Reject a base URL shaped so the API key sent to it could go astray.

    `url` ultimately comes from `.env` or the environment — an ancestor `.env`
    (see `_load_dotenv`) or a misconfigured deployment can set it to anything.
    User-info, a query string, or a fragment on an API base URL has no
    legitimate use here and is exactly how a redirect-and-harvest attempt would
    look (`https://real-host.example@evil.example/`). Plain HTTP sends the
    `X-API-Key` / bearer token in cleartext, which is fine for a loopback local
    model (Ollama, LM Studio) but not for anything reachable over a network —
    that requires an explicit opt-in via `allow_insecure_env`.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port  # accessing either can raise on a malformed URL
    except ValueError as e:
        # e.g. an unmatched IPv6 bracket ("http://[::1") or a non-numeric
        # port ("https://host:notaport/") — both raise here, uncaught,
        # rather than reaching the checks below that would otherwise reject
        # them cleanly.
        raise ConfigError(f"{name} is malformed: {e}") from e
    if parts.scheme not in ("http", "https"):
        raise ConfigError(f"{name} must be an http(s) URL, got {url!r}.")
    if parts.username or parts.password:
        raise ConfigError(f"{name} must not contain user-info (a login/password in the URL).")
    if parts.query or parts.fragment:
        raise ConfigError(f"{name} must not contain a query string or fragment.")
    if not host:
        raise ConfigError(f"{name} has no host.")
    insecure = parts.scheme == "http" and not _is_loopback(host)
    if insecure and not os.environ.get(allow_insecure_env):
        raise ConfigError(
            f"{name}={url!r} is plain HTTP to a non-loopback host — the API key would "
            f"travel in cleartext. Set {allow_insecure_env}=1 to override."
        )
    return url


@dataclass(frozen=True)
class CcConfig:
    api_key: str
    api_url: str = "https://crimsoncrawler.com/"

    @classmethod
    def from_env(cls) -> CcConfig:
        return cls(
            api_key=_require("CRIMSON_CRAWLER_API_KEY"),
            # `or default`, not get(name, default): an exported-but-empty var
            # ("BASE_URL=") should fall back, not become an empty base URL.
            api_url=_validated_base_url(
                "CRIMSON_CRAWLER_BASE_URL",
                os.environ.get("CRIMSON_CRAWLER_BASE_URL") or "https://crimsoncrawler.com/",
                allow_insecure_env="CC_ALLOW_INSECURE_CC_URL",
            ),
        )


@dataclass(frozen=True)
class OpenAIConfig:
    api_key: str
    model: str = "gpt-4o-mini"
    base_url: str | None = None  # set for Azure OpenAI / local (Ollama, LM Studio)
    # Per-request timeout. The SDK default is 600s, which across MAX_TURNS means
    # a stalled local model can hang the CLI for hours with no output. 60s is
    # generous for a tool-calling turn; raise it for slow local hardware.
    timeout: float = 60.0

    @classmethod
    def from_env(cls) -> OpenAIConfig:
        raw_base_url = os.environ.get("OPENAI_BASE_URL") or None
        return cls(
            api_key=_require("OPENAI_API_KEY"),
            model=os.environ.get("OPENAI_MODEL") or "gpt-4o-mini",
            base_url=(
                _validated_base_url(
                    "OPENAI_BASE_URL",
                    raw_base_url,
                    allow_insecure_env="CC_ALLOW_INSECURE_OPENAI_URL",
                )
                if raw_base_url
                else None
            ),
            timeout=_positive_float("OPENAI_TIMEOUT", 60.0),
        )
