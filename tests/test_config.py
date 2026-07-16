"""Tests for JSONX config parsing and validation (config.py)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from config import ServerConfig, load, parse_jsonx


# --------------------------------------------------------------------------- #
# JSONL record merging
# --------------------------------------------------------------------------- #

def test_single_record():
    assert parse_jsonx('{"host": "h", "port": 1}') == {"host": "h", "port": 1}


def test_records_merge_across_lines():
    text = '{"host": "h"}\n{"port": 1}'
    assert parse_jsonx(text) == {"host": "h", "port": 1}


def test_later_line_overrides_earlier():
    text = '{"port": 8765}\n{"port": 9000}'
    assert parse_jsonx(text) == {"port": 9000}


def test_blank_lines_ignored():
    assert parse_jsonx('\n\n{"a": 1}\n\n') == {"a": 1}


# --------------------------------------------------------------------------- #
# JSONC comments and trailing commas
# --------------------------------------------------------------------------- #

def test_hash_and_slash_line_comments():
    text = '# comment\n// another\n{"a": 1}'
    assert parse_jsonx(text) == {"a": 1}


def test_block_comment_stripped_and_lines_preserved():
    text = '/* multi\nline */\n{"a": 1}'
    assert parse_jsonx(text) == {"a": 1}


def test_inline_comment_after_record():
    assert parse_jsonx('{"a": 1}  // trailing note') == {"a": 1}


def test_trailing_comma_tolerated():
    assert parse_jsonx('{"a": 1, "b": 2,}') == {"a": 1, "b": 2}


def test_comment_markers_inside_strings_are_preserved():
    # // # /* */ and ,} inside string values must survive untouched.
    text = '{"url": "http://x//y", "note": "a,}b", "tag": "/* keep */"}'
    assert parse_jsonx(text) == {"url": "http://x//y", "note": "a,}b", "tag": "/* keep */"}


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

def test_non_object_record_rejected():
    with pytest.raises(ValueError, match="must be a JSON object"):
        parse_jsonx("[1, 2, 3]")


def test_invalid_json_reports_line_number():
    with pytest.raises(ValueError, match="line 2"):
        parse_jsonx('{"a": 1}\n{bad}')


# --------------------------------------------------------------------------- #
# load() + validation
# --------------------------------------------------------------------------- #

def test_load_missing_file_returns_defaults(tmp_path):
    cfg = load(str(tmp_path / "nope.cfg"))
    assert cfg == ServerConfig()
    assert cfg.host == "localhost" and cfg.port == 8765


def test_load_valid_file(tmp_path):
    path = tmp_path / "c.cfg"
    path.write_text('{"server_name": "n1"}\n{"host": "0.0.0.0", "port": 9001}')
    cfg = load(str(path))
    assert cfg.server_name == "n1"
    assert cfg.host == "0.0.0.0"
    assert cfg.port == 9001


def test_unknown_key_rejected(tmp_path):
    path = tmp_path / "c.cfg"
    path.write_text('{"prot": 8765}')  # typo for "port"
    with pytest.raises(ValidationError):
        load(str(path))


def test_out_of_range_port_rejected(tmp_path):
    path = tmp_path / "c.cfg"
    path.write_text('{"port": 70000}')
    with pytest.raises(ValidationError):
        load(str(path))
