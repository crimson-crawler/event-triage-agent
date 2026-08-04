"""Offline tests for config env handling and CLI input reading."""

from __future__ import annotations

import io
import os
import types
from pathlib import Path

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


def test_default_and_https_base_urls_are_accepted(monkeypatch):
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "k")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.delenv("CRIMSON_CRAWLER_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    assert CcConfig.from_env().api_url == "https://crimsoncrawler.com/"
    assert OpenAIConfig.from_env().base_url is None

    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", "https://cc.example.com/")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    assert CcConfig.from_env().api_url == "https://cc.example.com/"
    assert OpenAIConfig.from_env().base_url == "https://api.openai.com/v1"


def test_loopback_http_openai_base_url_is_accepted(monkeypatch):
    # Local models (Ollama, LM Studio) are documented to run over plain HTTP
    # on loopback — that must keep working without any override.
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
    assert OpenAIConfig.from_env().base_url == "http://localhost:11434/v1"
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:11434/v1")
    assert OpenAIConfig.from_env().base_url == "http://127.0.0.1:11434/v1"


@pytest.mark.parametrize(
    ("var", "url"),
    [
        ("CRIMSON_CRAWLER_BASE_URL", "https://user:pass@crimsoncrawler.com/"),
        ("CRIMSON_CRAWLER_BASE_URL", "https://crimsoncrawler.com/?x=1"),
        ("CRIMSON_CRAWLER_BASE_URL", "https://crimsoncrawler.com/#frag"),
        ("CRIMSON_CRAWLER_BASE_URL", "ftp://crimsoncrawler.com/"),
        ("CRIMSON_CRAWLER_BASE_URL", "http://cc.internal.example.com/"),
        ("OPENAI_BASE_URL", "https://user:pass@api.example.com/v1"),
        ("OPENAI_BASE_URL", "http://api.example.com/v1"),  # non-loopback plain HTTP
    ],
)
def test_unsafe_base_url_is_a_config_error(monkeypatch, var, url):
    # User-info, a query/fragment, a non-http(s) scheme, or plain HTTP to a
    # non-loopback host are all shapes a credential-harvesting redirect would
    # take — refuse them the same way _load_dotenv refuses to trust them.
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "k")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.delenv("CC_ALLOW_INSECURE_CC_URL", raising=False)
    monkeypatch.delenv("CC_ALLOW_INSECURE_OPENAI_URL", raising=False)
    monkeypatch.setenv(var, url)
    with pytest.raises(ConfigError):
        (CcConfig if var.startswith("CRIMSON") else OpenAIConfig).from_env()


def test_insecure_base_url_override_is_honoured(monkeypatch):
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "k")
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", "http://cc.internal.example.com/")
    monkeypatch.setenv("CC_ALLOW_INSECURE_CC_URL", "1")
    assert CcConfig.from_env().api_url == "http://cc.internal.example.com/"


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1",  # unmatched IPv6 bracket — urlsplit() itself raises
        "https://host:notaport/",  # non-numeric port — .port access raises
    ],
)
def test_malformed_base_url_is_a_config_error_not_a_crash(monkeypatch, url):
    # Both raise a bare ValueError out of urlsplit()/`.port` if uncaught,
    # producing a traceback instead of the clean exit(2) every other bad
    # setting in this module gets via ConfigError.
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "k")
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", url)
    with pytest.raises(ConfigError):
        CcConfig.from_env()


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


def test_ancestor_dotenv_is_not_loaded(tmp_path, monkeypatch):
    # Used to be found by walking up from the invocation directory and loaded
    # with only a warning — enough for a planted ancestor .env to redirect the
    # base URLs and collect the real API key on the first request. There is
    # no upward search at all now: an ancestor .env is simply never found.
    (tmp_path / ".env").write_text("CRIMSON_CRAWLER_BASE_URL=https://attacker.test/\n")
    work = tmp_path / "nested" / "deeper"
    work.mkdir(parents=True)
    monkeypatch.chdir(work)
    monkeypatch.delenv("CRIMSON_CRAWLER_BASE_URL", raising=False)
    config._load_dotenv()
    assert os.environ.get("CRIMSON_CRAWLER_BASE_URL") is None


def test_cwd_dotenv_is_loaded(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("CC_TEST_MARKER=from-cwd\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CC_TEST_MARKER", raising=False)
    config._load_dotenv()
    assert os.environ.get("CC_TEST_MARKER") == "from-cwd"


def test_dotenv_symlink_outside_cwd_is_refused_by_default(tmp_path, monkeypatch, capsys):
    # ./.env reached through a symlink to elsewhere is an ancestor file wearing
    # a local name — refuse it the same way, don't just trust the local path.
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    real_env = outside / "real.env"
    real_env.write_text("CC_TEST_MARKER=from-symlink\n")
    work = tmp_path / "work"
    work.mkdir()
    (work / ".env").symlink_to(real_env)
    monkeypatch.chdir(work)
    monkeypatch.delenv("CC_TEST_MARKER", raising=False)
    config._load_dotenv()
    assert os.environ.get("CC_TEST_MARKER") is None
    assert "symlink" in capsys.readouterr().err


def test_dotenv_symlink_inside_cwd_is_loaded(tmp_path, monkeypatch):
    # A symlink pointing *inside* the current directory (`.env ->
    # config/prod.env`) is a same-project reorganization, not an ancestor
    # escape — refusing it was a false positive with a misleading "outside
    # the current directory" message, since the target is inside.
    work = tmp_path / "work"
    (work / "config").mkdir(parents=True)
    (work / "config" / "prod.env").write_text("CC_TEST_MARKER=from-inside-symlink\n")
    (work / ".env").symlink_to(Path("config") / "prod.env")
    monkeypatch.chdir(work)
    monkeypatch.delenv("CC_TEST_MARKER", raising=False)
    config._load_dotenv()
    assert os.environ.get("CC_TEST_MARKER") == "from-inside-symlink"


def test_cc_dotenv_explicit_path_is_loaded_even_outside_cwd(tmp_path, monkeypatch):
    outside = tmp_path / "elsewhere" / "creds.env"
    outside.parent.mkdir()
    outside.write_text("CC_TEST_MARKER=from-explicit-path\n")
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setenv("CC_DOTENV", str(outside))
    monkeypatch.delenv("CC_TEST_MARKER", raising=False)
    config._load_dotenv()
    assert os.environ.get("CC_TEST_MARKER") == "from-explicit-path"


def test_cc_dotenv_missing_path_warns(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CC_DOTENV", str(tmp_path / "nope.env"))
    config._load_dotenv()
    assert "does not exist" in capsys.readouterr().err
