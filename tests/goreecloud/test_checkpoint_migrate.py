"""No-clobber trusted-local checkpoint conversion with explicit opt-in."""
import hashlib
import os
import pickle
import subprocess
import sys
from pathlib import Path

import pytest

from scrapling.spiders.checkpoint import CheckpointData
from scrapling.spiders.checkpoint_migrate import migrate_trusted_local_checkpoint
from scrapling.spiders.request import Request
from scrapling.spiders._checkpoint_json import decode_checkpoint_json


def _local_legacy(directory: Path) -> bytes:
    original = CheckpointData(
        requests=[
            Request("https://example.invalid/item", sid="local", priority=3,
                    meta={"blob": b"\x00\xff"}, data=b"test", proxy="http://proxy.invalid/"),
        ],
        seen={b"\x00", "historic"},
    )
    source = pickle.dumps(original)
    (directory / "checkpoint.pkl").write_bytes(source)
    return source


def test_trusted_migration_dry_run_does_not_touch_source_or_create_target(tmp_path: Path):
    source = _local_legacy(tmp_path)
    summary = migrate_trusted_local_checkpoint(tmp_path, confirmed_trusted=True)
    assert summary["requests"] == 1 and summary["seen"] == 2
    assert summary["written"] is False
    assert summary["source_sha256"] == hashlib.sha256(source).hexdigest()
    assert not (tmp_path / "checkpoint.json").exists()
    assert (tmp_path / "checkpoint.pkl").read_bytes() == source


def test_trusted_migration_writes_separate_private_verified_file(tmp_path: Path):
    source = _local_legacy(tmp_path)
    summary = migrate_trusted_local_checkpoint(tmp_path, confirmed_trusted=True, write=True)
    assert summary["written"] is True
    output = tmp_path / "checkpoint.json"
    assert output.is_file()
    if os.name == "posix":
        assert output.stat().st_mode & 0o077 == 0
    raw = output.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == summary["json_sha256"]
    data = decode_checkpoint_json(raw)
    assert len(data.requests) == 1
    assert data.requests[0].meta == {"blob": b"\x00\xff"}
    assert data.requests[0]._session_kwargs["proxy"] == "http://proxy.invalid/"
    assert data.seen == {b"\x00", "historic"}
    assert (tmp_path / "checkpoint.pkl").read_bytes() == source
    assert not list(tmp_path.glob(".checkpoint-json-migrate-*"))


def test_converter_never_overwrites_existing_json(tmp_path: Path):
    source = _local_legacy(tmp_path)
    target = tmp_path / "checkpoint.json"
    target.write_bytes(b"existing-private-state")
    with pytest.raises(FileExistsError):
        migrate_trusted_local_checkpoint(tmp_path, confirmed_trusted=True, write=True)
    assert target.read_bytes() == b"existing-private-state"
    assert (tmp_path / "checkpoint.pkl").read_bytes() == source


def test_converter_refuses_pickle_without_explicit_trust(tmp_path: Path):
    source = _local_legacy(tmp_path)
    with pytest.raises(ValueError, match="trust confirmation"):
        migrate_trusted_local_checkpoint(tmp_path, write=True)
    assert (tmp_path / "checkpoint.pkl").read_bytes() == source
    assert not (tmp_path / "checkpoint.json").exists()


def test_converter_refuses_symlinked_crawl_directory_and_source(tmp_path: Path):
    private = tmp_path / "private"
    private.mkdir()
    source = _local_legacy(private)
    alias = tmp_path / "linked"
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(ValueError):
        migrate_trusted_local_checkpoint(alias, confirmed_trusted=True, write=True)
    (private / "checkpoint.pkl").unlink()
    (private / "checkpoint.pkl").symlink_to(tmp_path / "outside.pkl")
    (tmp_path / "outside.pkl").write_bytes(source)
    with pytest.raises(ValueError):
        migrate_trusted_local_checkpoint(private, confirmed_trusted=True, write=True)
    assert not (private / "checkpoint.json").exists()


def test_converter_rejects_unsupported_state_and_keeps_source(tmp_path: Path):
    request = Request("https://example.invalid/", meta={"not_supported": {1, 2}})
    source = pickle.dumps(CheckpointData(requests=[request]))
    (tmp_path / "checkpoint.pkl").write_bytes(source)
    with pytest.raises(ValueError):
        migrate_trusted_local_checkpoint(tmp_path, confirmed_trusted=True, write=True)
    assert (tmp_path / "checkpoint.pkl").read_bytes() == source
    assert not (tmp_path / "checkpoint.json").exists()


def test_converter_refuses_final_link_race_without_overwriting(tmp_path: Path, monkeypatch):
    _local_legacy(tmp_path)
    import scrapling.spiders.checkpoint_migrate as module

    original_link = module.os.link

    def conflict(src, dest, *, follow_symlinks):
        Path(dest).write_bytes(b"other-writer-output")
        raise FileExistsError("destination created during conversion")

    monkeypatch.setattr(module.os, "link", conflict)
    with pytest.raises(FileExistsError):
        migrate_trusted_local_checkpoint(tmp_path, confirmed_trusted=True, write=True)
    assert (tmp_path / "checkpoint.json").read_bytes() == b"other-writer-output"
    assert not list(tmp_path.glob(".checkpoint-json-migrate-*"))
    monkeypatch.setattr(module.os, "link", original_link)


def test_cli_requires_trusted_flag_even_for_dry_run(tmp_path: Path):
    _local_legacy(tmp_path)
    command = [sys.executable, "-m", "scrapling.spiders.checkpoint_migrate",
               "--crawl-dir", str(tmp_path)]
    denied = subprocess.run(command, capture_output=True, text=True, timeout=20)
    assert denied.returncode != 0
    assert "confirm-trusted-local-file" in denied.stderr
    assert not (tmp_path / "checkpoint.json").exists()
    success = subprocess.run(command + ["--confirm-trusted-local-file"], capture_output=True, text=True, timeout=20)
    assert success.returncode == 0, success.stderr
    assert "not written" in success.stdout
    assert not (tmp_path / "checkpoint.json").exists()
    created = subprocess.run(
        command + ["--confirm-trusted-local-file", "--write"],
        capture_output=True, text=True, timeout=20,
    )
    assert created.returncode == 0, created.stderr
    assert "created new" in created.stdout
    assert (tmp_path / "checkpoint.json").is_file()

def test_converter_rejects_dangling_output_symlink(tmp_path: Path):
    source = _local_legacy(tmp_path)
    (tmp_path / "checkpoint.json").symlink_to(tmp_path / "does-not-exist")
    with pytest.raises(FileExistsError):
        migrate_trusted_local_checkpoint(tmp_path, confirmed_trusted=True, write=True)
    assert (tmp_path / "checkpoint.pkl").read_bytes() == source


def test_converter_rejects_source_changes_before_publication(tmp_path: Path, monkeypatch):
    _local_legacy(tmp_path)
    import scrapling.spiders.checkpoint_migrate as module

    original = module._read_checkpoint_bytes
    reads = [0]

    def changed_at_second_read(path):
        reads[0] += 1
        if reads[0] == 2:
            (tmp_path / "checkpoint.pkl").write_bytes(b"changed-by-synthetic-fixture")
        return original(path)

    monkeypatch.setattr(module, "_read_checkpoint_bytes", changed_at_second_read)
    with pytest.raises(RuntimeError, match="changed"):
        migrate_trusted_local_checkpoint(tmp_path, confirmed_trusted=True, write=True)
    assert not (tmp_path / "checkpoint.json").exists()
    assert not list(tmp_path.glob(".checkpoint-json-migrate-*"))
