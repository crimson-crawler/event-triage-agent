#!/usr/bin/env python3
"""Convenience entry point for running from a repo checkout.

The real CLI lives in ``cc_agent.cli`` (also exposed as the ``cc-agent``
console script after ``pip install``). This shim keeps ``python run.py``
working for local development.
"""

from cc_agent.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
