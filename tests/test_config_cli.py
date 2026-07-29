"""Offline tests for config env handling and CLI input reading."""

from __future__ import annotations

import io
import types

import pytest

from cc_agent import config
from cc_agent.cli import MAX_INPUT_CHARS, _read_input
from cc_agent.config import CcConfig, ConfigError, OpenAIConfig


def test_empty_env_vars_fall_back_to_defaults(monkeypatch):
    # An exported-but-empty var must use the default, not become an empty value.
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "k")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", "")
    monkeypatch.setenv("OPENAI_MODEL", "")
    assert CcConfig.from_env().api_url == "https://crimsoncrawler.com/"
    assert OpenAIConfig.from_env().model == "gpt-4o-mini"


def test_read_input_missing_file_exits_cleanly():
    # A missing --file must be a clean exit(2), not a raw traceback.
    args = types.SimpleNamespace(input=None, file="/nonexistent/path.json")
    with pytest.raises(SystemExit) as exc:
        _read_input(args)
    assert exc.value.code == 2


def test_timeout_defaults_and_parses(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.delenv("OPENAI_TIMEOUT", raising=False)
    assert OpenAIConfig.from_env().timeout == 60.0
    monkeypatch.setenv("OPENAI_TIMEOUT", "180")
    assert OpenAIConfig.from_env().timeout == 180.0


@pytest.mark.parametrize("bad", ["nope", "0", "-5", "nan", "inf", "-inf", "Infinity"])
def test_invalid_timeout_is_a_config_error(monkeypatch, bad):
    # nan and inf both pass a bare `<= 0` check (nan compares False to
    # everything; inf is > 0) and would otherwise reach the client as the exact
    # unbounded-hang timeout this setting exists to prevent.
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("OPENAI_TIMEOUT", bad)
    with pytest.raises(ConfigError):
        OpenAIConfig.from_env()


def test_oversized_input_exits_cleanly():
    # The observation is sent to the model on every turn, so an unbounded read
    # is an unbounded bill. Over the cap must be exit(2), not a silent send.
    args = types.SimpleNamespace(input="x" * (MAX_INPUT_CHARS + 1), file=None)
    with pytest.raises(SystemExit) as exc:
        _read_input(args)
    assert exc.value.code == 2


def test_oversized_file_exits_cleanly(tmp_path):
    big = tmp_path / "huge.json"
    big.write_text("y" * (MAX_INPUT_CHARS + 10), encoding="utf-8")
    args = types.SimpleNamespace(input=None, file=str(big))
    with pytest.raises(SystemExit) as exc:
        _read_input(args)
    assert exc.value.code == 2


def test_input_at_the_limit_is_accepted():
    args = types.SimpleNamespace(input="z" * MAX_INPUT_CHARS, file=None)
    assert len(_read_input(args)) == MAX_INPUT_CHARS


def test_stdin_trailing_whitespace_does_not_push_content_over_the_cap(monkeypatch):
    # Content that is genuinely at the cap, plus a trailing newline from a pipe
    # (the common case), must still be accepted — stripping has to happen
    # before the bound check, not after.
    stdin = io.StringIO("z" * MAX_INPUT_CHARS + "\n")
    monkeypatch.setattr(stdin, "isatty", lambda: False)
    monkeypatch.setattr("sys.stdin", stdin)
    args = types.SimpleNamespace(input=None, file=None)
    assert len(_read_input(args)) == MAX_INPUT_CHARS


def test_oversized_stdin_content_still_exits_cleanly(monkeypatch):
    stdin = io.StringIO("z" * (MAX_INPUT_CHARS + 1))
    monkeypatch.setattr(stdin, "isatty", lambda: False)
    monkeypatch.setattr("sys.stdin", stdin)
    args = types.SimpleNamespace(input=None, file=None)
    with pytest.raises(SystemExit) as exc:
        _read_input(args)
    assert exc.value.code == 2


def test_malformed_dotenv_warns_instead_of_vanishing(tmp_path, monkeypatch, capsys):
    # Used to disappear into `except Exception: pass`, leaving the user with a
    # bare "KEY is not set" and no clue their .env had failed.
    env = tmp_path / ".env"
    env.write_bytes(b"\xff\xfe not valid utf-8 \x00")
    monkeypatch.chdir(tmp_path)
    config._load_dotenv()
    err = capsys.readouterr().err
    assert "could not read" in err or "loading .env" in err


def test_dotenv_from_an_ancestor_directory_is_announced(tmp_path, monkeypatch, capsys):
    # find_dotenv walks upward, so a planted ancestor .env can redirect the base
    # URLs and collect the key. Real env vars still win, but say something.
    (tmp_path / ".env").write_text("CRIMSON_CRAWLER_BASE_URL=https://attacker.test/\n")
    work = tmp_path / "nested" / "deeper"
    work.mkdir(parents=True)
    monkeypatch.chdir(work)
    config._load_dotenv()
    assert "outside the current directory" in capsys.readouterr().err
