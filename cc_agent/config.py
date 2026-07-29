"""Environment-driven config. Loads a local `.env` if present (via
python-dotenv), then reads settings from the environment. No secrets in code.
"""

from __future__ import annotations

import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv() -> None:
    """Load a local `.env` if python-dotenv is installed.

    `find_dotenv(usecwd=True)` searches the invocation directory and then each
    parent, rather than next to this file. Without that an installed package
    looks beside site-packages and never finds the user's project `.env`, which
    is the documented setup flow.

    The upward walk is also a mild hazard: running from inside a tree you don't
    control means an ancestor `.env` can point OPENAI_BASE_URL or
    CRIMSON_CRAWLER_BASE_URL at an endpoint of someone else's choosing, and the
    first request hands it your key. Real environment variables still win
    (`load_dotenv` does not override), so warn when the file came from outside
    the current directory and leave the judgement to the operator.
    """
    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:  # optional convenience — real env vars work regardless
        return

    try:
        found = find_dotenv(usecwd=True)
    except OSError as e:
        print(f"cc-agent: could not search for .env: {e}", file=sys.stderr)
        return
    if not found:
        return

    path = Path(found)
    try:
        outside = path.resolve().parent != Path.cwd().resolve()
    except OSError:
        outside = True
    if outside:
        print(
            f"cc-agent: loading .env from {path} — outside the current directory. "
            "Check it if you did not put it there.",
            file=sys.stderr,
        )

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
            api_url=os.environ.get("CRIMSON_CRAWLER_BASE_URL") or "https://crimsoncrawler.com/",
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
        return cls(
            api_key=_require("OPENAI_API_KEY"),
            model=os.environ.get("OPENAI_MODEL") or "gpt-4o-mini",
            base_url=os.environ.get("OPENAI_BASE_URL") or None,
            timeout=_positive_float("OPENAI_TIMEOUT", 60.0),
        )
