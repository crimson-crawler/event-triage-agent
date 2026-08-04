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
  swallowed by a blanket `except Exception: pass`.
- README: the "Untrusted input" section no longer claims the output contract
  "can't be overridden". It describes what is prompt-level mitigation and what is
  enforced in code, and states that verdicts are advisory.
- README/SECURITY.md's egress-filtering claims are scoped to what they
  actually are: a shape-based recognizer that refuses internal indicators in
  recognizable forms — stopping careless disclosure and the common/accidental
  case, not a determined injection — and one that only governs what reaches
  Crimson Crawler, not what reaches the configured model endpoint (the full
  observation goes there regardless; a local model via `OPENAI_BASE_URL`
  covers that leg too). Previously read as a flat guarantee that a
  manipulated run "doesn't leak your internal network on the way."
- Packaging metadata now declares authors, project URLs, keywords, and
  classifiers.

### Security

- **`.env` is no longer found by searching upward.** It previously walked from
  the invocation directory through every parent and loaded the first `.env`
  found, warning only if that file lived outside the current directory —
  enough for anyone who can plant a file above wherever an operator runs
  `cc-agent` to redirect `OPENAI_BASE_URL` / `CRIMSON_CRAWLER_BASE_URL` and
  collect the real API key on the first request. It is now loaded only from an
  explicit `CC_DOTENV` path or exactly `./.env`. A `./.env` reached through a
  symlink pointing outside the current directory tree is refused the same way;
  one pointing to a file *inside* the tree (e.g. `.env -> config/prod.env`) is
  loaded, since anything already writable inside the project is already
  trusted.
- **Both base URLs are validated.** `CRIMSON_CRAWLER_BASE_URL` and
  `OPENAI_BASE_URL` are rejected if they carry user-info, a query string, or a
  fragment (the shape of a credential-harvesting redirect), or if they're
  plain `http://` to a non-loopback host (the API key would travel in
  cleartext) — override the latter per-URL with `CC_ALLOW_INSECURE_CC_URL` /
  `CC_ALLOW_INSECURE_OPENAI_URL`. A malformed URL (an unmatched IPv6 bracket, a
  non-numeric port) is a clean `ConfigError` rather than an uncaught
  `ValueError` traceback.
- **Every tool's arguments are now rebuilt from an allowlist, not forwarded as
  the model produced them.** Previously only `enrich_ioc` was validated; the
  other five tools forwarded whatever dict the model produced, including any
  extra property. A crafted alert could steer a model into putting an internal
  hostname or a confidential field into `enrich_software.search`, or onto an
  extra property tacked onto an otherwise-valid `enrich_ioc` call, and it would
  reach the third-party CC endpoint unchanged. `cve_id` and `technique_id` are
  now checked against their expected shape (`CVE-YYYY-NNNN`, `T####[.###]`),
  and free-text name/id fields (`search`, `software_id`, `group_id`,
  `campaign_id`) are refused if they look like a URL or an email address,
  contain a reserved/internal IP or hostname anywhere in the text — tokenized
  so an address glued to trailing punctuation (`internal-db01.local:445`,
  `fileserver.internal/share`) or embedded in a sentence
  (`beacon observed from an RFC1918 host`, including bare IPv6 like `fe80::1`) is
  still caught, not just a value that is nothing but the address; a public IP
  mentioned in prose is deliberately still sent — or match a recognizable
  secret shape (AWS/GitHub/Slack/OpenAI-style key, a JWT, a PEM private-key
  header, or a `password: <value>` pattern — the same category `gitleaks`
  already scans for at publish time) rather than an actual name — and an
  unrecognised property on any tool call is refused outright. Defanged
  notation (`fileserver[.]internal`, `dc01(.)corp`, a full-width or
  ideographic full stop) is folded back to a plain `.` before the hostname
  checks run, in both this and `enrich_ioc`'s own hostname/domain check —
  it's the conventional way analysts write hostnames in tickets and vendor
  advisories, not a contrived evasion, so it's the form an internal name is
  likely to arrive in during ordinary use. `enrich_ioc`'s own URL check (`_check_url`) gets the same
  malformed-URL fix as the base-URL validation above; that path is
  model-triggered, not just operator-config-triggered. Tool schemas also now
  declare `additionalProperties: false`. `include` accepts any
  section-name-shaped token, not only `"details"` — a hard-coded single value
  would have refused the "expand the include list in a follow-up call"
  behavior `system_prompt.md` explicitly asks the model for.
- Publish tooling: the internal-marker deny-list was extended (bare `def-logix`
  domains, capitalised `/home/<User>` paths, link-local, CGNAT, loopback, and
  internal collaboration hosts) and now has a self-test, so the fail-closed gate
  is verified rather than assumed. CI container images are pinned by digest,
  including the image that runs the pre-publish secret scan. The publish token is
  no longer passed in the `git push` URL.
- **CI now fails if `uv.lock` drifts from `pyproject.toml`** (`uv lock --check`,
  the `lock_check` job) — previously every job used `uv sync --frozen`, which
  trusts the lock as-is and would silently keep testing against a stale
  resolution after a dependency bump landed without a matching `uv lock`.
- **A CycloneDX SBOM of the locked runtime dependencies** (`sbom.cdx.json`) is
  generated on every pipeline and shipped in the published snapshot alongside
  each release, so a consumer has a machine-readable dependency manifest
  without re-resolving it themselves.
- The build backend requirement is now bounded (`hatchling>=1.24,<2`) rather
  than open-ended — `pip install .` resolves it independently of `uv.lock`, so
  an unbounded requirement meant two installs of the same commit, done months
  apart, could run different build-backend code.

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
