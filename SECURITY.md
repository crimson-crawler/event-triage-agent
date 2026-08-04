# Security policy

## Reporting a vulnerability

Please report security issues **privately**, through GitHub's private
vulnerability reporting:

**https://github.com/crimson-crawler/event-triage-agent/security/advisories/new**

That channel is visible only to the maintainers until an advisory is published.
Please do **not** open a public issue for a suspected vulnerability.

Useful things to include, as far as you have them:

- what you did, and what happened
- the affected file or behaviour
- how you'd tell a real issue from a false alarm
- anything that limits or widens the impact

We aim to acknowledge a report within 5 business days. If a fix is warranted
we'll agree a disclosure timeline with you before publishing.

## Scope

This repository is `cc-agent` — a demo triage agent that calls the Crimson
Crawler enrichment API. In scope:

- the CLI and the agent loop (`cc_agent/`)
- the system prompt (`cc_agent/system_prompt.md`), including prompt-injection
  behaviour
- the packaging and dependency configuration

The Crimson Crawler API itself is **not** in this repository. For issues in the
API, see [crimsoncrawler.com](https://crimsoncrawler.com).

## What this tool does and does not guarantee

Worth stating plainly, because it shapes what counts as a vulnerability:

- **Verdicts are advisory.** The observation and every enrichment response are
  attacker-reachable text. The system prompt instructs the model to treat them
  as data, and the agent validates that the final verdict matches the documented
  contract — but neither prevents a model from being misled about the *content*
  of its answer. Output is for an analyst to review, not to action automatically.
- **Indicators leave your network — the CC leg is filtered, the model leg is
  not.** The full observation is sent to the configured model endpoint
  regardless of what it contains; on a hosted provider (OpenAI, Azure OpenAI)
  that data has already left before any of the checks below run. Only the
  Crimson Crawler leg is filtered: reserved IP ranges, bare hostnames, and
  internal DNS zones — including common defanged notation
  (`fileserver[.]internal`) — are refused in code before any CC request is
  made, and every tool argument is rebuilt from an allowlist rather than
  forwarded as the model produced it, so an unexpected property or a smuggled
  URL/address/credential in a name field is refused the same way (see
  `cc_agent/tools.py`). This is a shape-based recognizer, not a closed
  defense — it catches the forms above, including the conventional/accidental
  case, not every encoding a sufficiently steered model might choose (spacing
  a hostname out, spelling "dot" as a word, base64, splitting a value across
  calls). Set `CC_INTERNAL_SUFFIXES` to add your own zones. If the model leg
  needs the same guarantee, point `OPENAI_BASE_URL` at a local model so
  nothing on that leg leaves your network either.
- **Config can't be silently redirected to another endpoint.** `.env` is only
  loaded from an explicit `CC_DOTENV` path or exactly `./.env` — never from a
  parent directory or through a symlink pointing outside it — and both base
  URLs are rejected if they carry user-info, a query/fragment, or plain HTTP
  to a non-loopback host (see `cc_agent/config.py`).
- **No sandbox.** The agent has six read-only HTTP tools. It executes no shell
  command, writes no file, and loads no plugin. A report that it *can* be made
  to do any of those would be a serious finding.

## Supported versions

This is a v0.x demo. Only the latest published snapshot is supported; fixes go
to the current release rather than to older ones.
