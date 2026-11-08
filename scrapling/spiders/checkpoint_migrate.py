"""Guarded, offline conversion from a *trusted local* pickle to opt-in JSON v1.

This is NOT a safe parser for checkpoints from others. The restricted legacy
unpickler is still pickle. The converter never overwrites either format and
does not delete source files. Run only on an inactive, backed-up crawl dir.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from pathlib import Path

from scrapling.spiders._checkpoint_json import decode_checkpoint_json, encode_checkpoint_json
from scrapling.spiders.checkpoint import (
    _decode_legacy_checkpoint_bytes,
    _read_checkpoint_bytes,
)


def migrate_trusted_local_checkpoint(
    crawl_dir: str | Path,
    *,
    confirmed_trusted: bool = False,
    write: bool = False,
) -> dict:
    """Plan or perform no-clobber local migration, preserving checkpoint.pkl.

    Requires explicit trust acknowledgment even in dry-run mode, because both
    modes must deserialize the inherited local pickle. A write uses an
    O_EXCL-equivalent hard-link publication of a private fsynced temp file.
    """
    if confirmed_trusted is not True:
        raise ValueError("Explicit trust confirmation is required for legacy pickle")
    directory = Path(crawl_dir)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Crawl directory must be a real existing directory")
    source = directory / "checkpoint.pkl"
    destination = directory / "checkpoint.json"
    if os.path.lexists(destination):
        raise FileExistsError("Refusing to replace existing checkpoint.json")
    if source.is_symlink():
        raise ValueError("Legacy checkpoint symlinks are not allowed")

    # All parsing and encoding occurs before any target file is created.
    # One source read supplies exactly the bytes that are validated/converted.
    legacy_bytes = _read_checkpoint_bytes(source)
    legacy_hash = hashlib.sha256(legacy_bytes).hexdigest()
    data = _decode_legacy_checkpoint_bytes(legacy_bytes)
    encoded = encode_checkpoint_json(data)
    restored = decode_checkpoint_json(encoded)
    if (
        len(restored.requests) != len(data.requests)
        or restored.seen != data.seen
        or encode_checkpoint_json(restored) != encoded
    ):
        raise ValueError("Decoded JSON checkpoint did not preserve basic state")
    if _read_checkpoint_bytes(source) != legacy_bytes:
        raise RuntimeError("Legacy checkpoint changed during conversion; stop the crawler")

    result = {
        "requests": len(data.requests),
        "seen": len(data.seen),
        "source_sha256": legacy_hash,
        "json_sha256": hashlib.sha256(encoded).hexdigest(),
        "written": False,
    }
    if not write:
        return result

    # Create a private temporary file and publish its inode under the new
    # filename only when the name does not exist. os.replace would overwrite.
    fd, scratch = tempfile.mkstemp(prefix=".checkpoint-json-migrate-", suffix=".tmp", dir=directory)
    published = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if _read_checkpoint_bytes(source) != legacy_bytes:
            raise RuntimeError("Legacy checkpoint changed before JSON publication")
        os.link(scratch, destination, follow_symlinks=False)
        published = True
    finally:
        if os.path.lexists(scratch):
            os.unlink(scratch)
    if not published:
        raise RuntimeError("JSON checkpoint publication failed")
    # Report success only after comparing published bytes and decoding.
    published_bytes = _read_checkpoint_bytes(destination)
    if published_bytes != encoded or decode_checkpoint_json(published_bytes).seen != data.seen:
        raise RuntimeError("Published JSON checkpoint failed integrity readback")
    if _read_checkpoint_bytes(source) != legacy_bytes:
        raise RuntimeError("Legacy checkpoint changed after JSON publication; review both copies")
    result["written"] = True
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline, no-clobber conversion of an owner-created *trusted local* "
            "checkpoint.pkl to checkpoint.json; NEVER use imported/untrusted pickle files"
        ),
    )
    parser.add_argument("--crawl-dir", required=True, type=Path, help="Stopped local crawler directory")
    parser.add_argument(
        "--confirm-trusted-local-file", action="store_true",
        help="Required: explicitly confirm the pickle was created in your private trusted directory",
    )
    parser.add_argument(
        "--write", action="store_true",
        help="Publish checkpoint.json without overwrite after validation (default: dry run)",
    )
    args = parser.parse_args(argv)
    if not args.confirm_trusted_local_file:
        parser.error("Legacy pickle requires --confirm-trusted-local-file even for a dry run")
    try:
        summary = migrate_trusted_local_checkpoint(
            args.crawl_dir, confirmed_trusted=True, write=args.write,
        )
    except Exception as exc:
        # CLI boundary: never echo a possibly secret-bearing path, URL or
        # checkpoint field from an exception raised while parsing local state.
        parser.exit(1, f"Migration refused: {type(exc).__name__}\n")
    action = "created new" if summary["written"] else "validated, not written"
    print(
        f"JSON checkpoint {action}: requests={summary['requests']}, "
        f"seen={summary['seen']}; original pickle retained"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
