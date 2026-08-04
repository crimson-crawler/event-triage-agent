# Contributing

## This repository is a published snapshot

Read this first, because it changes what a pull request can do here.

The GitHub repository is a **one-way mirror**. Each release replaces the whole
tree with a single fresh commit, so:

- there is **no commit history** — `git log` shows one commit
- **pull requests cannot be merged here**, and a commit pushed to `main` would be
  overwritten by the next release
- forking is disabled

This is deliberate: development happens in a private repository, and only a
sanitized snapshot is published. It is not a judgement about outside
contributions — it's a constraint of how the code gets here.

## What is useful

- **Bug reports** — [open an issue](https://github.com/crimson-crawler/event-triage-agent/issues).
  A reproduction, the model and endpoint you used, and the output you got are the
  three things that make a report actionable.
- **Security issues** — do not open an issue. See [SECURITY.md](SECURITY.md).
- **Suggested changes** — an issue describing the change is more useful than a
  pull request, since we can't merge the latter. A patch or diff pasted into the
  issue is welcome and we'll credit you if we apply it.
- **Questions about the Crimson Crawler API** — see
  [crimsoncrawler.com](https://crimsoncrawler.com).

## Working on the code locally

```bash
git clone https://github.com/crimson-crawler/event-triage-agent
cd event-triage-agent
pip install ".[dev]"

pytest                  # offline — no network, no keys
ruff check .
ruff format --check .
```

Or, for the exact resolution CI tests against: `uv sync --frozen --extra dev`. If
you touch `pyproject.toml`'s dependencies, run `uv lock` (not just `uv add`/`uv
remove`, if you edit the file by hand) so `uv.lock` stays in sync — CI's
`lock_check` job (`uv lock --check`) fails the pipeline otherwise.

The test suite mocks all network access (`httpx.MockTransport` plus an injected
fake OpenAI client), so it needs no API keys and contacts nothing.

Two conventions if you're proposing a change:

- **Line length 100**, and `ruff format` is authoritative — run it rather than
  hand-formatting.
- **Comments explain *why*, not *what*.** The existing code is deliberately
  written this way; a comment that restates the line above it will get removed.

## Scope

The project is intentionally small — see the "Scope" section of the
[README](README.md#scope) for what is deliberately absent. Changes that keep it
readable in one sitting are much more likely to land than ones that broaden it.
