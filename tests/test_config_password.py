"""Tests for the Covenant password config (config.py env handling)."""

from __future__ import annotations

from config import (
    ServerConfig,
    load_with_env,
    password_from_env,
)


# --------------------------------------------------------------------------- #
# password_from_env precedence
# --------------------------------------------------------------------------- #

def test_priestly_passwd_wins():
    env = {"PRIESTLY_PASSWD": "primary", "PASSWD": "fallback"}
    assert password_from_env(env) == "primary"


def test_passwd_fallback():
    assert password_from_env({"PASSWD": "fallback"}) == "fallback"


def test_no_env_returns_none():
    assert password_from_env({}) is None


def test_empty_string_treated_as_unset():
    assert password_from_env({"PRIESTLY_PASSWD": ""}) is None


# --------------------------------------------------------------------------- #
# password_required property
# --------------------------------------------------------------------------- #

def test_password_required_true_when_set():
    assert ServerConfig(password="x").password_required is True


def test_password_required_false_when_none():
    assert ServerConfig().password_required is False


def test_password_required_false_when_empty():
    assert ServerConfig(password="").password_required is False


# --------------------------------------------------------------------------- #
# load_with_env override
# --------------------------------------------------------------------------- #

def test_env_overrides_file(tmp_path):
    cfg_file = tmp_path / "c.cfg"
    cfg_file.write_text('{"server_name": "n"}\n{"password": "from-file"}')
    cfg = load_with_env(str(cfg_file), env={"PRIESTLY_PASSWD": "from-env"})
    assert cfg.password == "from-env"


def test_file_password_used_when_no_env(tmp_path):
    cfg_file = tmp_path / "c.cfg"
    cfg_file.write_text('{"password": "from-file"}')
    cfg = load_with_env(str(cfg_file), env={})
    assert cfg.password == "from-file"


def test_open_node_when_neither(tmp_path):
    cfg_file = tmp_path / "c.cfg"
    cfg_file.write_text('{"server_name": "open-node"}')
    cfg = load_with_env(str(cfg_file), env={})
    assert cfg.password is None
    assert cfg.password_required is False
