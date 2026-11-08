"""Checkpoint persistence with explicitly restricted, bounded pickle loading.

The imported format remains compatible with ordinary CheckpointData/Request records,
but externally supplied or altered pickle classes are never constructed. Checkpoints
are local, private state and must not be imported from untrusted sources.
"""
import io
import os
import pickle
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import anyio
from anyio import Path as AsyncPath

from scrapling.core.utils import log
from scrapling.core._types import Set, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from scrapling.spiders.request import Request

# Limit persistent state to avoid excessive allocations from untrusted files.
MAX_CHECKPOINT_BYTES = 64 * 1024 * 1024


@dataclass
class CheckpointData:
    """Container for checkpoint state."""

    requests: List["Request"] = field(default_factory=list)
    seen: Set[bytes] = field(default_factory=set)


class _RestrictedCheckpointUnpickler(pickle.Unpickler):
    """Only instantiate the two known data types and standard set containers."""

    _ALLOWED = {
        ("scrapling.spiders.checkpoint", "CheckpointData"),
        ("scrapling.spiders.request", "Request"),
        ("builtins", "set"),
        ("builtins", "frozenset"),
    }

    def find_class(self, module: str, name: str):
        if (module, name) not in self._ALLOWED:
            raise pickle.UnpicklingError(f"Disallowed checkpoint object: {module}.{name}")
        if module == "builtins":
            return {"set": set, "frozenset": frozenset}[name]
        if name == "CheckpointData":
            return CheckpointData
        from scrapling.spiders.request import Request
        return Request


def _read_checkpoint_bytes(path: Path) -> bytes:
    # On supported Unix hosts, O_NOFOLLOW prevents final-component symlink swaps.
    # O_NONBLOCK prevents a replaced FIFO from blocking the crawler indefinitely.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    if getattr(os, "O_NOFOLLOW", 0):
        flags |= os.O_NOFOLLOW
    elif path.is_symlink():
        raise ValueError("Checkpoint symlinks are not allowed")
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Checkpoint must be a regular file")
        if info.st_size > MAX_CHECKPOINT_BYTES:
            raise ValueError("Checkpoint exceeds size limit")
        content = f.read(MAX_CHECKPOINT_BYTES + 1)
    if len(content) > MAX_CHECKPOINT_BYTES:
        raise ValueError("Checkpoint exceeds size limit")
    return content


def _decode_legacy_checkpoint_bytes(raw: bytes) -> CheckpointData:
    """Validate a previously read local pickle byte snapshot; never trust external files."""
    source = io.BytesIO(raw)
    data = _RestrictedCheckpointUnpickler(source).load()
    if source.read(1):
        # A valid checkpoint is exactly one pickle stream. Do not silently
        # accept extra serialized objects or concealed trailing payloads.
        raise ValueError("Checkpoint has unexpected trailing data")
    from scrapling.spiders.request import Request
    if not isinstance(data, CheckpointData):
        raise ValueError("Checkpoint data type is invalid")
    if not isinstance(data.requests, list) or not all(
        isinstance(item, Request) for item in data.requests
    ):
        raise ValueError("Checkpoint request records are invalid")
    if not isinstance(data.seen, set) or not all(
        isinstance(item, (bytes, str)) for item in data.seen
    ):
        raise ValueError("Checkpoint seen fingerprints are invalid")
    for request in data.requests:
        # find_class only prevents unexpected Python classes; a crafted pickle
        # can still set arbitrary malformed fields on an allowed Request.
        # Check fields consumed later by the crawler before returning it.
        state = vars(request)
        if (
            not isinstance(state.get("url"), str)
            or not isinstance(state.get("sid"), str)
            or type(state.get("priority")) is not int
            or type(state.get("dont_filter")) is not bool
            or not isinstance(state.get("meta"), dict)
            or type(state.get("_retry_count")) is not int
            or state["_retry_count"] < 0
            or not isinstance(state.get("_session_kwargs"), dict)
            or state.get("callback", object()) is not None
            or not (
                state.get("_fp") is None or isinstance(state.get("_fp"), bytes)
            )
        ):
            raise ValueError("Checkpoint request state is invalid")
        callback_name = state.get("_callback_name")
        if callback_name is not None and (
            not isinstance(callback_name, str)
            or len(callback_name) > 256
            or not callback_name.isidentifier()
            or (callback_name.startswith("__") and callback_name.endswith("__"))
        ):
            raise ValueError("Checkpoint callback name is invalid")
    return data


def _read_checkpoint(path: Path) -> CheckpointData:
    """Read the inherited restricted legacy pickle checkpoint."""
    return _decode_legacy_checkpoint_bytes(_read_checkpoint_bytes(path))


def _atomic_checkpoint_write(path: Path, data: bytes) -> None:
    if len(data) > MAX_CHECKPOINT_BYTES:
        raise ValueError("Checkpoint exceeds size limit")
    fd, name = tempfile.mkstemp(prefix=".checkpoint-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


class CheckpointManager:
    """Manages saving and loading checkpoint state to/from disk.

    Legacy pickle data is accepted only when its objects are on the fixed allowlist.
    Arbitrary Python classes and symlinks are rejected without deserialization.
    """

    CHECKPOINT_FILE = "checkpoint.pkl"

    def __init__(
        self, crawldir: str | Path | AsyncPath, interval: float = 300.0,
        *, checkpoint_format: str = "pickle",
    ):
        if checkpoint_format not in ("pickle", "json_v1"):
            raise ValueError("checkpoint_format must be 'pickle' or 'json_v1'")
        self.checkpoint_format = checkpoint_format
        self.crawldir = AsyncPath(crawldir)
        filename = "checkpoint.json" if checkpoint_format == "json_v1" else self.CHECKPOINT_FILE
        self._checkpoint_path = self.crawldir / filename
        self.interval = interval
        if not isinstance(interval, (int, float)):
            raise TypeError("Checkpoints interval must be integer or float.")
        elif interval < 0:
            raise ValueError("Checkpoints interval must be equal or greater than 0.")

    async def has_checkpoint(self) -> bool:
        return await self._checkpoint_path.exists()

    async def save(self, data: CheckpointData) -> None:
        """Save checkpoint atomically with private (0600) temporary permissions."""
        await self.crawldir.mkdir(parents=True, exist_ok=True)
        try:
            if self.checkpoint_format == "json_v1":
                from scrapling.spiders._checkpoint_json import encode_checkpoint_json
                serialized = encode_checkpoint_json(data)
            else:
                serialized = pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
            await anyio.to_thread.run_sync(
                _atomic_checkpoint_write, Path(self._checkpoint_path), serialized
            )
            log.info(f"Checkpoint saved: {len(data.requests)} requests, {len(data.seen)} seen URLs")
        except Exception as e:
            log.error(f"Failed to save checkpoint: {e}")
            raise

    async def load(self) -> Optional[CheckpointData]:
        """Load allowed local records; fail closed for corrupt/untrusted state."""
        if not await self.has_checkpoint():
            return None
        try:
            if self.checkpoint_format == "json_v1":
                from scrapling.spiders._checkpoint_json import decode_checkpoint_json
                raw = await anyio.to_thread.run_sync(
                    _read_checkpoint_bytes, Path(self._checkpoint_path)
                )
                data = decode_checkpoint_json(raw)
            else:
                data = await anyio.to_thread.run_sync(
                    _read_checkpoint, Path(self._checkpoint_path)
                )
            log.info(f"Checkpoint loaded: {len(data.requests)} requests, {len(data.seen)} seen URLs")
            return data
        except Exception as e:
            log.error(f"Failed to load checkpoint (starting fresh): {e}")
            return None

    async def cleanup(self) -> None:
        """Delete checkpoint file after successful completion."""
        try:
            if await self._checkpoint_path.exists():
                await self._checkpoint_path.unlink()
            log.debug("Checkpoint file cleaned up")
        except Exception as e:
            log.warning(f"Failed to cleanup checkpoint file: {e}")
