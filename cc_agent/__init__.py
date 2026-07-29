"""cc-agent — an open-source threat-triage agent powered by Crimson Crawler.

A tool-calling agent that runs against any OpenAI-compatible endpoint: it
enriches a security observation via the CC API and returns a triage verdict.
"""

from importlib.resources import files

__version__ = "0.1.0"


def system_prompt() -> str:
    """The agent's system prompt, shipped as package data (system_prompt.md)."""
    return files(__package__).joinpath("system_prompt.md").read_text(encoding="utf-8")
