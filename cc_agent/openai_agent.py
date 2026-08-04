"""Local backend: run the agent against any OpenAI-compatible endpoint.

The model is given the six CC tools and the shared system prompt, and we run
the tool-calling loop: call the model → execute any CC tool calls it requests →
feed the results back → repeat until it returns a final answer (the verdict) or
we hit the iteration cap.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from openai import OpenAI

from . import system_prompt
from .cc_client import CcClient
from .config import CcConfig, OpenAIConfig
from .tools import TOOLS, dispatch

# Bound on model↔tool round-trips, so a misbehaving loop can't run forever.
# An alert with a handful of identifiers + two-step resolutions fits well under.
MAX_TURNS = 12

# Bound on total CC requests per run. MAX_TURNS alone is not enough: a single
# turn may contain one tool call per identifier, so an observation carrying a few
# hundred CVE ids — and the observation is attacker-reachable text — could burn a
# month of the free tier's 150-request quota in one invocation.
MAX_TOOL_CALLS = 24

# Bound on one tool result before it re-enters the conversation. tools.py already
# asks the model for include=['details'] because the default "can return 100+ KB
# on popular entities", but that is guidance, not a limit.
MAX_TOOL_RESULT_CHARS = 24_000

# The TriageVerdict contract, as stated to the model in system_prompt.md.
REQUIRED_VERDICT_FIELDS = (
    "verdict",
    "confidence",
    "reasoning",
    "recommended_actions",
    "evidence_chain",
)
VERDICT_VALUES = frozenset({"true_positive", "likely_false_positive", "needs_escalation"})
CONFIDENCE_VALUES = frozenset({"low", "medium", "high"})


@dataclass
class AgentResult:
    """What the run produced: the model's final text (the verdict JSON) plus a
    trace of which tools were called with what — useful for `--verbose`."""

    output: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    turns: int = 0


def _escalation(reasoning: str) -> str:
    """A contract-shaped needs_escalation verdict, for when we can't produce one."""
    return json.dumps(
        {
            "verdict": "needs_escalation",
            "confidence": "low",
            "reasoning": reasoning,
            "recommended_actions": ["Review manually."],
            "evidence_chain": [],
        }
    )


def _validated(output: str) -> str:
    """Return `output` if it satisfies the TriageVerdict contract, else escalate.

    system_prompt.md tells the model the contract is fixed, but a system prompt
    is a request, not a guarantee — the observation and every tool response are
    attacker-reachable, so a successful injection can return prose, a forged
    verdict, or nothing at all. This does not prevent injection. It ensures a
    manipulated or simply sloppy run degrades to "a human should look at this"
    instead of handing the caller something that merely reads like a verdict.
    """
    try:
        parsed = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return _escalation("Model did not return valid JSON; verdict unverified.")
    if not isinstance(parsed, dict):
        return _escalation("Model returned JSON that is not an object; verdict unverified.")

    missing = [f for f in REQUIRED_VERDICT_FIELDS if f not in parsed]
    if missing:
        return _escalation(f"Model verdict is missing required field(s): {', '.join(missing)}.")
    # isinstance first: an unhashable value (a dict, a list) would make the
    # membership test itself raise.
    if not isinstance(parsed["verdict"], str) or parsed["verdict"] not in VERDICT_VALUES:
        return _escalation(f"Model returned an unrecognised verdict: {parsed['verdict']!r}.")
    if not isinstance(parsed["confidence"], str) or parsed["confidence"] not in CONFIDENCE_VALUES:
        return _escalation(f"Model returned an unrecognised confidence: {parsed['confidence']!r}.")
    for list_field in ("recommended_actions", "evidence_chain"):
        if not isinstance(parsed[list_field], list):
            return _escalation(f"Model returned {list_field!r} as a non-list.")
    return output


def _capped(result: str) -> str:
    """Cap one tool result, keeping the truncation visible to the model."""
    if len(result) <= MAX_TOOL_RESULT_CHARS:
        return result
    return json.dumps(
        {
            "truncated": True,
            "original_chars": len(result),
            "partial": result[:MAX_TOOL_RESULT_CHARS],
        }
    )


def run_agent(
    user_input: str,
    *,
    cc_config: CcConfig | None = None,
    openai_config: OpenAIConfig | None = None,
    cc: CcClient | None = None,
    client: Any | None = None,
) -> AgentResult:
    """Triage `user_input` (an alert JSON, a description, or a bare indicator).

    Config/clients are injectable for tests; otherwise built from env.
    """
    cc_config = cc_config or CcConfig.from_env()
    openai_config = openai_config or OpenAIConfig.from_env()
    client = client or OpenAI(
        api_key=openai_config.api_key,
        base_url=openai_config.base_url,
        timeout=openai_config.timeout,
    )

    own_cc = cc is None
    cc = cc or CcClient(cc_config.api_url, cc_config.api_key)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt()},
        {"role": "user", "content": user_input},
    ]
    trace: list[dict[str, Any]] = []
    calls_made = 0
    try:
        for turn in range(1, MAX_TURNS + 1):
            resp = client.chat.completions.create(
                model=openai_config.model,
                messages=messages,
                tools=TOOLS,
            )
            msg = resp.choices[0].message
            tool_calls = msg.tool_calls or []
            if not tool_calls:
                return AgentResult(
                    output=_validated(msg.content or ""), tool_calls=trace, turns=turn
                )

            # Echo the assistant turn (with its tool_calls) back into history,
            # then answer each tool call with a `tool` message.
            messages.append(msg.model_dump(exclude_none=True))
            for call in tool_calls:
                name = call.function.name
                raw_args = call.function.arguments or "{}"
                try:
                    args = json.loads(raw_args)
                except json.JSONDecodeError:
                    args = None
                # Malformed / non-object arguments: don't fabricate an empty
                # call (that would hit the paid API with a wrong query and give
                # the model no signal to correct itself) — return an error so it
                # retries with valid JSON. Costs no budget: nothing was sent.
                if not isinstance(args, dict):
                    trace.append(
                        {"tool": name, "arguments": raw_args, "error": "invalid_arguments"}
                    )
                    result = json.dumps(
                        {
                            "error": (
                                f"invalid tool arguments (expected a JSON object): {raw_args[:200]}"
                            )
                        }
                    )
                elif calls_made >= MAX_TOOL_CALLS:
                    trace.append({"tool": name, "arguments": args, "error": "budget_exhausted"})
                    result = json.dumps(
                        {
                            "error": (
                                f"tool-call budget of {MAX_TOOL_CALLS} exhausted — produce the "
                                "verdict from the evidence already gathered"
                            )
                        }
                    )
                else:
                    calls_made += 1
                    result = _capped(dispatch(cc, name, args))
                    trace.append({"tool": name, "arguments": args})
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": result,
                    }
                )
        # Ran out of turns without a final answer.
        return AgentResult(
            output=_escalation(f"Agent did not converge within {MAX_TURNS} turns."),
            tool_calls=trace,
            turns=MAX_TURNS,
        )
    finally:
        if own_cc:
            cc.close()
