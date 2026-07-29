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
- **Indicators leave your network.** Extracted indicators are sent to the
  configured Crimson Crawler endpoint, and the observation is sent to the
  configured model endpoint. Reserved ranges, bare hostnames, and internal DNS
  zones are refused in code before any request (see `cc_agent/tools.py`); set
  `CC_INTERNAL_SUFFIXES` to add your own zones.
- **No sandbox.** The agent has six read-only HTTP tools. It executes no shell
  command, writes no file, and loads no plugin. A report that it *can* be made
  to do any of those would be a serious finding.

## Supported versions

This is a v0.x demo. Only the latest published snapshot is supported; fixes go
to the current release rather than to older ones.
