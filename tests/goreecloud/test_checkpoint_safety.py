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

@pytest.mark.asyncio
async def test_rejects_trailing_pickle_data(tmp_path: Path):
    """Do not accept extra serialized objects hidden after a valid checkpoint."""
    payload = pickle.dumps(CheckpointData())
    (tmp_path / "checkpoint.pkl").write_bytes(payload + pickle.dumps({"hidden": "payload"}))
    assert await CheckpointManager(tmp_path).load() is None
    (tmp_path / "checkpoint.pkl").write_bytes(payload + b"unrelated-trailer")
    assert await CheckpointManager(tmp_path).load() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("field,bad_value", [
    ("url", 123),
    ("sid", 123),
    ("priority", True),
    ("dont_filter", 1),
    ("meta", ["wrong"]),
    ("_retry_count", -3),
    ("_session_kwargs", ["wrong"]),
    ("_fp", "not-fingerprint-bytes"),
])
async def test_rejects_malformed_allowed_request_state(tmp_path: Path, field, bad_value):
    """Allowed Request class is insufficient if its fields were forged."""
    request = Request("https://example.org/", priority=2)
    setattr(request, field, bad_value)
    (tmp_path / "checkpoint.pkl").write_bytes(pickle.dumps(
        CheckpointData(requests=[request], seen={b"valid"})
    ))
    assert await CheckpointManager(tmp_path).load() is None


class _ForgedRequestState:
    """Inert pickle reduction naming only the allowed Request class."""

    def __reduce__(self):
        # Request.__getstate__ intentionally clears callback, so a genuinely
        # malformed callback needs a crafted state for the allowlisted class.
        return (Request, ("https://example.org/",), {"callback": 9})


@pytest.mark.asyncio
async def test_rejects_forged_allowed_request_callback_state(tmp_path: Path):
    data = CheckpointData(requests=[_ForgedRequestState()])
    (tmp_path / "checkpoint.pkl").write_bytes(pickle.dumps(data))
    assert await CheckpointManager(tmp_path).load() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("callback_name", ["__getattribute__", "not.an.identifier", "", "X" * 257])
async def test_rejects_invalid_restored_callback_name(tmp_path: Path, callback_name: str):
    request = Request("https://example.org/")
    def local_callback(*args):
        return None
    local_callback.__name__ = callback_name
    request.callback = local_callback
    # The original Request.__getstate__ serializes only the callback name,
    # not this function object.
    (tmp_path / "checkpoint.pkl").write_bytes(pickle.dumps(
        CheckpointData(requests=[request])
    ))
    assert await CheckpointManager(tmp_path).load() is None


@pytest.mark.asyncio
async def test_legacy_well_typed_pickle_is_still_supported(tmp_path: Path):
    """Preserve the prior on-disk format and ordinary custom callback names."""
    def parse_details(*args):
        return None
    request = Request(
        "https://example.org/items",
        sid="scraper-session",
        priority=-2,
        dont_filter=True,
        meta={"nested": {"a": [1, 2, None]}},
        proxy="http://proxy.example.test:8080",
    )
    request.callback = parse_details
    (tmp_path / "checkpoint.pkl").write_bytes(pickle.dumps(
        CheckpointData(requests=[request], seen={b"raw-fp", "historical"})
    ))
    loaded = await CheckpointManager(tmp_path).load()
    assert loaded is not None
    assert loaded.requests[0].url == request.url
    assert loaded.requests[0].priority == -2
    assert loaded.requests[0]._callback_name == "parse_details"
    assert loaded.requests[0]._session_kwargs["proxy"] == "http://proxy.example.test:8080"
    assert loaded.seen == {b"raw-fp", "historical"}
