# Changelog

All notable changes to `cc-agent`.

Because the public repository is a snapshot mirror with no commit history (see
[CONTRIBUTING.md](CONTRIBUTING.md)), this file is the record of what changed
between published versions.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project aims at [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `enrich_ioc` arguments are now validated **in code** before any request. Reserved
  IP ranges (RFC1918, loopback, link-local, CGNAT, multicast, reserved), bare
  hostnames with no domain, and internal DNS zones (`.local`, `.internal`,
  `.corp`, …) are refused rather than sent to the enrichment API. Previously this
  rule lived only in the system prompt, so a crafted observation could walk
  internal indicators out to a third party. Set `CC_INTERNAL_SUFFIXES` to add
  site-specific zones. RFC 5737/3849 documentation ranges are still accepted.
- `type` is now checked against the shape of `value` (hash length and hex,
  URL scheme, IP parse, email form), so a mismatched pair is refused instead of
  becoming a wasted paid request.
- The model's final message is validated against the documented `TriageVerdict`
  contract. A response that is not JSON, is missing a required field, or carries
  an unrecognised `verdict`/`confidence` degrades to a `needs_escalation`
  verdict explaining why, rather than being passed through as if it were valid.
- `MAX_TOOL_CALLS` (24) bounds total enrichment requests per run. `MAX_TURNS`
  alone did not: one turn may contain a tool call per identifier, so a crafted
  observation could exhaust a month of the free tier's quota in one invocation.
- Tool results are capped at 24,000 characters before re-entering the
  conversation, with the truncation flagged to the model.
- Observations are capped at 200,000 characters (`--input`, `--file`, stdin) with
  a clean `exit 2`.
- `OPENAI_TIMEOUT` (default 60s) — the SDK default of 600s meant a stalled local
  model could hang the CLI for hours with no output.
- `SECURITY.md`, `CONTRIBUTING.md`, and this changelog.

### Fixed

- `OPENAI_TIMEOUT` now rejects `nan` and `inf`/`-inf`. Both pass a bare `<= 0`
  check (`nan` compares `False` to everything; `inf` is `> 0`), so either would
  have reached the client as a non-positive or unbounded timeout — the exact
  hang this setting exists to prevent.
- Stdin input that is exactly at the 200,000-character cap plus a trailing
  newline (the common case for piped input) is no longer rejected. The bound
  check now runs after stripping, not before, matching `--input` and `--file`.

### Changed

- A malformed or unreadable `.env` now reports the problem instead of being
  swallowed by a blanket `except Exception: pass`. Loading a `.env` found in a
  *parent* directory is announced on stderr, since an ancestor file can redirect
  the base URLs.
- README: the "Untrusted input" section no longer claims the output contract
  "can't be overridden". It describes what is prompt-level mitigation and what is
  enforced in code, and states that verdicts are advisory.
- Packaging metadata now declares authors, project URLs, keywords, and
  classifiers.

### Security

- Publish tooling: the internal-marker deny-list was extended (bare `def-logix`
  domains, capitalised `/home/<User>` paths, link-local, CGNAT, loopback, and
  internal collaboration hosts) and now has a self-test, so the fail-closed gate
  is verified rather than assumed. CI container images are pinned by digest,
  including the image that runs the pre-publish secret scan. The publish token is
  no longer passed in the `git push` URL.

## [0.1.0]

Initial release.

- Triage a security observation — full alert JSON, a short description, or a bare
  indicator — into a structured `TriageVerdict`.
- Six Crimson Crawler enrichment tools (`enrich_cve`, `enrich_technique`,
  `enrich_ioc`, `enrich_software`, `enrich_group`, `enrich_campaign`) offered to
  the model, which decides which are worth calling.
- Runs against any OpenAI-compatible endpoint (OpenAI, Azure OpenAI, or a local
  server via Ollama / LM Studio / vLLM).
- `cc-agent` console script plus a `python run.py` shim; `--input`, `--file`,
  `--json`, and `--verbose` flags, with stdin as the default source.
- Offline test suite — all network mocked, no keys required.
