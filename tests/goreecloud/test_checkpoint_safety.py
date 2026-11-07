"""Downstream regression tests for untrusted checkpoint files."""
import os
import pickle
from pathlib import Path

import pytest
from scrapling.spiders.checkpoint import CheckpointManager, CheckpointData, MAX_CHECKPOINT_BYTES
from scrapling.spiders.request import Request


class _UntrustedPayload:
    def __reduce__(self):
        # Constructing the bytes is inert; an unsafe loader would run the command.
        return (os.system, ("exit 7",))


@pytest.mark.asyncio
async def test_untrusted_global_rejected(tmp_path: Path):
    (tmp_path / "checkpoint.pkl").write_bytes(pickle.dumps(_UntrustedPayload()))
    assert await CheckpointManager(tmp_path).load() is None


@pytest.mark.asyncio
async def test_roundtrip_private_permissions(tmp_path: Path):
    manager = CheckpointManager(tmp_path)
    await manager.save(CheckpointData(
        requests=[Request("https://example.org/", priority=5)],
        seen={b"fingerprint", "historic"},
    ))
    if os.name == "posix":
        assert (tmp_path / "checkpoint.pkl").stat().st_mode & 0o077 == 0
    data = await manager.load()
    assert data is not None
    assert data.requests[0].url == "https://example.org/"
    assert data.requests[0].priority == 5
    assert data.seen == {b"fingerprint", "historic"}


@pytest.mark.asyncio
async def test_symlink_rejected(tmp_path: Path):
    (tmp_path / "target.pkl").write_bytes(pickle.dumps(CheckpointData()))
    try:
        (tmp_path / "checkpoint.pkl").symlink_to(tmp_path / "target.pkl")
    except (NotImplementedError, OSError):
        pytest.skip("Symlinks unavailable")
    assert await CheckpointManager(tmp_path).load() is None


@pytest.mark.asyncio
async def test_size_limit(tmp_path: Path):
    path = tmp_path / "checkpoint.pkl"
    with path.open("wb") as f:
        f.truncate(MAX_CHECKPOINT_BYTES + 1)
    assert await CheckpointManager(tmp_path).load() is None


@pytest.mark.asyncio
async def test_invalid_shape(tmp_path: Path):
    (tmp_path / "checkpoint.pkl").write_bytes(pickle.dumps({"requests": []}))
    assert await CheckpointManager(tmp_path).load() is None
