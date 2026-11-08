"""Bounded, opt-in, non-executable checkpoint format and compatibility tests."""
import hashlib
import json
import os
import pickle
from pathlib import Path

import pytest

from scrapling.spiders._checkpoint_json import (
    MAX_JSON_ATOM_BYTES,
    decode_checkpoint_json,
    encode_checkpoint_json,
)
from scrapling.spiders.checkpoint import CheckpointData, CheckpointManager
from scrapling.spiders.request import Request


def _callback(*args):
    return None


def _sample() -> CheckpointData:
    request = Request(
        "https://example.invalid/items",
        sid="local",
        priority=-3,
        dont_filter=True,
        meta={"headers": { "a": b"\x00\xff"}, "items": (True, 4, None, 1.5)},
        data=b"\x00\x01", headers={"X-Test": "value"},
    )
    request.callback = _callback
    request._fp = b"\x10" * 20
    return CheckpointData(requests=[request], seen={b"\x00\xff", "old-key"})


def _rechecksum(document: dict) -> bytes:
    payload = json.dumps(document["data"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    document["sha256"] = hashlib.sha256(payload).hexdigest()
    return (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


@pytest.mark.asyncio
async def test_json_checkpoint_roundtrip_and_atomic_permissions(tmp_path: Path):
    manager = CheckpointManager(tmp_path, checkpoint_format="json_v1")
    assert manager._checkpoint_path == tmp_path / "checkpoint.json"
    source = _sample()
    await manager.save(source)
    raw = (tmp_path / "checkpoint.json").read_bytes()
    assert raw == encode_checkpoint_json(source)
    assert b"pickle" not in raw.lower()
    assert not (tmp_path / "checkpoint.pkl").exists()
    if os.name == "posix":
        assert (tmp_path / "checkpoint.json").stat().st_mode & 0o077 == 0
    loaded = await manager.load()
    assert loaded is not None
    assert loaded.seen == source.seen
    got = loaded.requests[0]
    assert got.url == source.requests[0].url
    assert got.priority == -3
    assert got._session_kwargs == source.requests[0]._session_kwargs
    assert got.meta == source.requests[0].meta
    assert got._fp == source.requests[0]._fp
    assert got._callback_name == "_callback"
    await manager.cleanup()
    assert not (tmp_path / "checkpoint.json").exists()


@pytest.mark.asyncio
async def test_opt_in_does_not_deserialize_or_remove_existing_pickle(tmp_path: Path):
    legacy = tmp_path / "checkpoint.pkl"
    legacy_bytes = pickle.dumps(_sample())
    legacy.write_bytes(legacy_bytes)
    manager = CheckpointManager(tmp_path, checkpoint_format="json_v1")
    assert not await manager.has_checkpoint()
    assert await manager.load() is None
    await manager.save(CheckpointData())
    await manager.cleanup()
    assert legacy.read_bytes() == legacy_bytes
    assert (await CheckpointManager(tmp_path).load()) is not None


def _deep_value():
    value = 1
    for _ in range(22):
        value = [value]
    return value


@pytest.mark.parametrize("bad", [
    {"arbitrary": "type"},
    {"url": object()},
    {"meta": {"nested": {1: "non-string key"}}},
    {"meta": {"value": object()}},
    {"meta": {"big": b"x" * (MAX_JSON_ATOM_BYTES + 1)}},
    {"meta": {"bad_float": float("nan")}},
    {"meta": {"deep": _deep_value()}},
])
def test_json_encoder_rejects_unsupported_or_oversized_state(bad):
    request = Request("https://example.invalid/")
    for key, value in bad.items():
        setattr(request, key, value)
    with pytest.raises((ValueError, RecursionError)):
        encode_checkpoint_json(CheckpointData(requests=[request]))


@pytest.mark.parametrize("mutation", [
    lambda d: d.update({"version": 2}),
    lambda d: d.update({"format": "wrong"}),
    lambda d: d["data"].update({"requests": {}}),
    lambda d: d["data"]["requests"][0].update({"t": "pickle"}),
    lambda d: d["data"]["requests"][0]["v"][0][1].update({"t": "object"}),
    lambda d: d["data"]["seen"].append(d["data"]["seen"][0]),
])
def test_json_decoder_rejects_untrusted_mutations(mutation):
    doc = json.loads(encode_checkpoint_json(_sample()))
    mutation(doc)
    with pytest.raises(ValueError):
        decode_checkpoint_json(_rechecksum(doc))


def test_json_decoder_refuses_checksum_tampering_and_duplicate_keys():
    raw = encode_checkpoint_json(_sample())
    document = json.loads(raw)
    document["data"]["seen"] = []
    with pytest.raises(ValueError, match="digest"):
        decode_checkpoint_json(json.dumps(document).encode())
    with pytest.raises(ValueError, match="Duplicate"):
        decode_checkpoint_json(b'{"version":1,"version":1}')


def test_json_decoder_refuses_unknown_top_level_fields():
    doc = json.loads(encode_checkpoint_json(_sample()))
    doc["danger"] = {"injected": True}
    with pytest.raises(ValueError):
        decode_checkpoint_json(_rechecksum(doc))


@pytest.mark.asyncio
async def test_json_checkpoint_rejects_symlinks(tmp_path: Path):
    outside = tmp_path / "outside.json"
    outside.write_bytes(encode_checkpoint_json(_sample()))
    (tmp_path / "checkpoint.json").symlink_to(outside)
    manager = CheckpointManager(tmp_path, checkpoint_format="json_v1")
    assert await manager.load() is None


@pytest.mark.asyncio
async def test_json_checkpoint_rejects_corruption_without_overwriting(tmp_path: Path):
    file = tmp_path / "checkpoint.json"
    file.write_text('{"version":1, "data":')
    manager = CheckpointManager(tmp_path, checkpoint_format="json_v1")
    assert await manager.load() is None
    assert file.read_text() == '{"version":1, "data":'


def test_json_format_choice_is_explicit():
    with pytest.raises(ValueError):
        CheckpointManager("/tmp/unused", checkpoint_format="json")
    assert CheckpointManager("/tmp/unused")._checkpoint_path.name == "checkpoint.pkl"


def test_json_bytes_encoding_is_deterministic():
    assert encode_checkpoint_json(_sample()) == encode_checkpoint_json(_sample())

@pytest.mark.asyncio
async def test_offline_legacy_to_json_migration_preserves_callback_name(tmp_path: Path):
    """Migration never deletes or updates the original checkpoint.pkl."""
    original = _sample()
    legacy_path = tmp_path / "checkpoint.pkl"
    legacy_path.write_bytes(pickle.dumps(original))
    legacy_digest = hashlib.sha256(legacy_path.read_bytes()).hexdigest()
    loaded = await CheckpointManager(tmp_path).load()
    assert loaded is not None
    assert loaded.requests[0]._callback_name == "_callback"
    json_manager = CheckpointManager(tmp_path, checkpoint_format="json_v1")
    await json_manager.save(loaded)
    restored = await json_manager.load()
    assert restored is not None
    assert restored.requests[0]._callback_name == "_callback"
    assert restored.requests[0].meta == original.requests[0].meta
    assert restored.requests[0]._session_kwargs == original.requests[0]._session_kwargs
    assert hashlib.sha256(legacy_path.read_bytes()).hexdigest() == legacy_digest


def test_spider_engine_selects_opt_in_json_without_changing_default(tmp_path: Path):
    from scrapling.spiders.spider import Spider
    from scrapling.spiders.engine import CrawlerEngine

    class DemoSpider(Spider):
        name = "json-checkpoint-test"
        async def parse(self, response):
            yield None

    default = DemoSpider(crawldir=tmp_path)
    assert default.checkpoint_format == "pickle"
    spider = DemoSpider(crawldir=tmp_path, checkpoint_format="json_v1")
    engine = CrawlerEngine(
        spider, spider._session_manager, spider.crawldir, spider._interval,
        checkpoint_format=spider.checkpoint_format,
    )
    assert engine._checkpoint_manager._checkpoint_path == tmp_path / "checkpoint.json"
    with pytest.raises(ValueError):
        DemoSpider(crawldir=tmp_path, checkpoint_format="other")

@pytest.mark.asyncio
async def test_engine_json_checkpoint_restore_preserves_pending_and_callback(tmp_path: Path):
    from scrapling.spiders.spider import Spider
    from scrapling.spiders.engine import CrawlerEngine

    class DemoSpider(Spider):
        name = "json-resume-integration"
        async def parse(self, response):
            yield None

    spider = DemoSpider(crawldir=tmp_path, checkpoint_format="json_v1")
    first = CrawlerEngine(
        spider, spider._session_manager, spider.crawldir, spider._interval,
        checkpoint_format=spider.checkpoint_format,
    )
    pending = Request("https://example.invalid/resume", sid="default", callback=spider.parse, priority=2)
    await first._checkpoint_manager.save(CheckpointData(requests=[pending], seen={b"seen-before"}))
    second = CrawlerEngine(
        spider, spider._session_manager, spider.crawldir, spider._interval,
        checkpoint_format=spider.checkpoint_format,
    )
    assert await second._restore_from_checkpoint() is True
    snapshot, seen = second.scheduler.snapshot()
    assert seen == {b"seen-before"}
    assert len(snapshot) == 1
    assert snapshot[0].url == pending.url
    assert snapshot[0].callback == spider.parse


def test_json_decoder_rejects_deep_values_even_with_valid_checksum():
    doc = json.loads(encode_checkpoint_json(_sample()))
    deep = {"t": "int", "v": 1}
    for _ in range(30):
        deep = {"t": "list", "v": [deep]}
    # Insert a correctly checksummed maliciously deep but valid JSON graph.
    doc["data"]["requests"][0]["v"][1][1] = deep
    with pytest.raises(ValueError):
        decode_checkpoint_json(_rechecksum(doc))


def test_json_decoder_rejects_nonfinite_constants():
    raw = b'{"data": NaN, "format": "goreecloud-checkpoint-json", "sha256": "", "version": 1}'
    with pytest.raises(ValueError):
        decode_checkpoint_json(raw)
