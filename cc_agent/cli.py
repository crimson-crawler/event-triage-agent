#!/usr/bin/env python3
"""cc-agent CLI — triage a security observation with Crimson Crawler enrichment.

Examples:
    cc-agent --input "CVE-2023-21529 seen with T1566.001 from 203.0.113.42"
    cc-agent --file alert.json
    echo "Mimikatz detected on host FIN-WS-07" | cc-agent
"""

from __future__ import annotations

import argparse
import json
import sys

# Cap on the observation. The whole input is sent to the model on every turn, so
# an unbounded read is an unbounded token bill — and the input is routinely
# untrusted (a pasted email, an alert export). Generous for a real alert.
MAX_INPUT_CHARS = 200_000


def _bounded(text: str, source: str) -> str:
    if len(text) > MAX_INPUT_CHARS:
        print(
            f"cc-agent: {source} is over the {MAX_INPUT_CHARS}-character limit. "
            "Trim it to the relevant part and retry.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return text


def _read_input(args) -> str:
    if args.input:
        return _bounded(args.input, "--input")
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                # Read one past the limit so an oversized file is detected
                # without pulling all of it into memory.
                data = fh.read(MAX_INPUT_CHARS + 1)
        except (OSError, UnicodeDecodeError) as e:
            # A missing / unreadable / non-UTF-8 --file should be a one-line
            # error, not a raw traceback from a public CLI.
            print(f"cc-agent: cannot read --file {args.file!r}: {e}", file=sys.stderr)
            raise SystemExit(2) from e
        return _bounded(data, f"--file {args.file!r}")
    if not sys.stdin.isatty():
        # Strip before bounding: trailing whitespace (a trailing newline from a
        # pipe, in the common case) must not push content that is genuinely
        # under the cap over it.
        data = sys.stdin.read(MAX_INPUT_CHARS + 1).strip()
        if data:
            return _bounded(data, "stdin")
    return ""


def main() -> int:
    p = argparse.ArgumentParser(description="Triage a security observation with CC enrichment.")
    p.add_argument("--input", "-i", help="Observation text (alert, description, or indicator).")
    p.add_argument("--file", "-f", help="Read the observation from a file (JSON or text).")
    p.add_argument("--json", action="store_true", help="Print only the raw verdict JSON.")
    p.add_argument(
        "--verbose", "-v", action="store_true", help="Also print the CC tool-call trace."
    )
    args = p.parse_args()

    observation = _read_input(args)
    if not observation:
        p.error("no input — pass --input, --file, or pipe text on stdin.")

    from cc_agent.config import ConfigError
    from cc_agent.openai_agent import run_agent

    try:
        result = run_agent(observation)
    except ConfigError as e:
        print(f"cc-agent: {e}", file=sys.stderr)
        return 2
    output, trace = result.output, result.tool_calls

    if args.verbose and trace:
        print("# CC tool calls:", file=sys.stderr)
        for c in trace:
            print(f"  {c['tool']}({json.dumps(c['arguments'])})", file=sys.stderr)

    # Pretty-print if the model returned clean JSON; else print as-is.
    if args.json:
        print(output)
    else:
        try:
            print(json.dumps(json.loads(output), indent=2))
        except (json.JSONDecodeError, TypeError):
            print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
