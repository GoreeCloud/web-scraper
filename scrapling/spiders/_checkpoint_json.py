"""Opt-in, versioned checkpoint JSON codec. Never deserializes Python classes.

The inherited pickle format remains the default for compatibility. JSON v1 is
an explicit opt-in and rejects unsupported types rather than dropping state.
The SHA-256 detects accidental corruption, not a malicious writer.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
from dataclasses import dataclass

MAX_JSON_CHECKPOINT_BYTES = 64 * 1024 * 1024
MAX_JSON_ATOM_BYTES = 2 * 1024 * 1024
MAX_JSON_TREE_NODES = 200_000
MAX_JSON_DEPTH = 16
_FORMAT = "goreecloud-checkpoint-json"
_REQUEST_FIELDS = frozenset({
    "url", "sid", "callback", "priority", "dont_filter", "meta",
    "_retry_count", "_session_kwargs", "_fp", "_callback_name",
})


@dataclass
class _Budget:
    nodes: int = 0

    def enter(self, depth: int) -> None:
        self.nodes += 1
        if depth > MAX_JSON_DEPTH or self.nodes > MAX_JSON_TREE_NODES:
            raise ValueError("Checkpoint nested structure exceeds safety limits")


def _atom_size(value: str | bytes) -> None:
    if len(value.encode("utf-8") if isinstance(value, str) else value) > MAX_JSON_ATOM_BYTES:
        raise ValueError("Checkpoint string or byte value exceeds size limit")


def _pack(value: object, budget: _Budget, depth: int = 0) -> dict:
    budget.enter(depth)
    if value is None:
        return {"t": "none"}
    if type(value) is bool:
        return {"t": "bool", "v": value}
    if type(value) is int:
        if value.bit_length() > 256:
            raise ValueError("Checkpoint integer exceeds size limit")
        return {"t": "int", "v": value}
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("Checkpoint float must be finite")
        return {"t": "float", "v": value}
    if type(value) is str:
        _atom_size(value)
        return {"t": "str", "v": value}
    if type(value) is bytes:
        _atom_size(value)
        return {"t": "bytes", "v": base64.b64encode(value).decode("ascii")}
    if type(value) in (list, tuple):
        if len(value) > MAX_JSON_TREE_NODES:
            raise ValueError("Checkpoint collection too large")
        return {
            "t": "list" if type(value) is list else "tuple",
            "v": [_pack(item, budget, depth + 1) for item in value],
        }
    if type(value) is dict:
        if len(value) > MAX_JSON_TREE_NODES or any(type(key) is not str for key in value):
            raise ValueError("Checkpoint mapping must use bounded string keys")
        pairs = []
        for key in sorted(value):
            _atom_size(key)
            pairs.append([key, _pack(value[key], budget, depth + 1)])
        return {"t": "dict", "v": pairs}
    raise ValueError(f"Unsupported checkpoint value type: {type(value).__name__}")


def _keys(item: object, expected: set[str]) -> dict:
    if type(item) is not dict or set(item) != expected:
        raise ValueError("Invalid checkpoint object shape")
    return item


def _unpack(value: object, budget: _Budget, depth: int = 0) -> object:
    budget.enter(depth)
    if type(value) is not dict or type(value.get("t")) is not str:
        raise ValueError("Invalid checkpoint value")
    kind = value["t"]
    if kind == "none":
        _keys(value, {"t"})
        return None
    item = _keys(value, {"t", "v"})["v"]
    if kind == "bool" and type(item) is bool:
        return item
    if kind == "int" and type(item) is int and item.bit_length() <= 256:
        return item
    if kind == "float" and type(item) is float and math.isfinite(item):
        return item
    if kind == "str" and type(item) is str:
        _atom_size(item)
        return item
    if kind == "bytes" and type(item) is str:
        if len(item) > (MAX_JSON_ATOM_BYTES * 4 // 3 + 8):
            raise ValueError("Checkpoint encoded bytes too large")
        try:
            binary = base64.b64decode(item, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("Invalid checkpoint base64") from exc
        _atom_size(binary)
        if base64.b64encode(binary).decode("ascii") != item:
            raise ValueError("Noncanonical checkpoint base64")
        return binary
    if kind in ("list", "tuple") and type(item) is list:
        if len(item) > MAX_JSON_TREE_NODES:
            raise ValueError("Checkpoint collection too large")
        items = [_unpack(child, budget, depth + 1) for child in item]
        return items if kind == "list" else tuple(items)
    if kind == "dict" and type(item) is list:
        if len(item) > MAX_JSON_TREE_NODES:
            raise ValueError("Checkpoint mapping too large")
        result = {}
        for pair in item:
            if type(pair) is not list or len(pair) != 2 or type(pair[0]) is not str:
                raise ValueError("Invalid checkpoint mapping pair")
            key = pair[0]
            _atom_size(key)
            if key in result:
                raise ValueError("Duplicate checkpoint mapping key")
            result[key] = _unpack(pair[1], budget, depth + 1)
        return result
    raise ValueError("Unsupported or malformed checkpoint value")


def _canonical(data: object) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _validate_request_state(state: dict) -> None:
    if (
        set(state) != _REQUEST_FIELDS
        or type(state["url"]) is not str
        or type(state["sid"]) is not str
        or type(state["priority"]) is not int
        or type(state["dont_filter"]) is not bool
        or type(state["meta"]) is not dict
        or type(state["_retry_count"]) is not int
        or state["_retry_count"] < 0
        or type(state["_session_kwargs"]) is not dict
        or state["callback"] is not None
        or (state["_fp"] is not None and type(state["_fp"]) is not bytes)
    ):
        raise ValueError("Unsupported or malformed JSON checkpoint request")
    name = state["_callback_name"]
    if name is not None and (
        type(name) is not str or len(name) > 256
        or not name.isidentifier()
        or (name.startswith("__") and name.endswith("__"))
    ):
        raise ValueError("Invalid JSON checkpoint callback name")


def encode_checkpoint_json(data: object) -> bytes:
    """Encode only the supported, explicit Request state; never pickle."""
    from scrapling.spiders.checkpoint import CheckpointData
    from scrapling.spiders.request import Request

    if type(data) is not CheckpointData or type(data.requests) is not list or type(data.seen) is not set:
        raise ValueError("Invalid checkpoint container")
    budget = _Budget()
    requests = []
    for request in data.requests:
        if type(request) is not Request:
            raise ValueError("Only ordinary Request objects can use JSON checkpoints")
        # A cached domain is derived from URL, not persistent request state.
        state = request.__getstate__().copy()
        state.pop("domain", None)
        # A restricted legacy pickle load stores its old callback name here.
        # Preserve it for explicit offline migration before a spider restores
        # the callable. Request.__getstate__ intentionally writes callback=None.
        if request.callback is None and hasattr(request, "_callback_name"):
            state["_callback_name"] = request._callback_name
        _validate_request_state(state)
        requests.append(_pack(state, budget))
    seen = []
    for entry in data.seen:
        if type(entry) not in (bytes, str):
            raise ValueError("Invalid checkpoint seen fingerprint")
        seen.append(_pack(entry, budget))
    seen.sort(key=_canonical)
    payload = {"requests": requests, "seen": seen}
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    output = _canonical({"format": _FORMAT, "version": 1, "sha256": digest, "data": payload}) + b"\n"
    if len(output) > MAX_JSON_CHECKPOINT_BYTES:
        raise ValueError("JSON checkpoint exceeds size limit")
    return output


def _reject_json_constant(value: str) -> object:
    raise ValueError("Nonfinite JSON checkpoint value")


def _check_untrusted_json_limits(
    value: object, budget: _Budget, depth: int = 0,
) -> None:
    """Bound raw JSON object traversal *before* canonical digest creation."""
    # The JSON wire representation adds type wrappers and pair arrays for
    # each inert value. Its structural depth/element count must therefore
    # have a distinct pre-hash ceiling from the decoded Python value depth.
    # _unpack() still enforces the strict MAX_JSON_DEPTH/MAX_JSON_TREE_NODES.
    budget.nodes += 1
    if depth > (MAX_JSON_DEPTH * 4 + 16) or budget.nodes > (MAX_JSON_TREE_NODES * 6):
        raise ValueError("Checkpoint raw JSON structure exceeds safety limits")
    if type(value) is str:
        if len(value) > (MAX_JSON_ATOM_BYTES * 4 // 3 + 8):
            raise ValueError("Checkpoint raw JSON string exceeds size limit")
    elif type(value) in (dict, list):
        if len(value) > MAX_JSON_TREE_NODES:
            raise ValueError("Checkpoint raw JSON container too large")
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError("Checkpoint raw JSON key invalid")
                _atom_size(key)
                _check_untrusted_json_limits(item, budget, depth + 1)
        else:
            for item in value:
                _check_untrusted_json_limits(item, budget, depth + 1)


def _unique_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON checkpoint key")
        result[key] = value
    return result


def decode_checkpoint_json(raw: bytes) -> object:
    """Parse bounded JSON into explicit, inert Request state only."""
    if type(raw) is not bytes or len(raw) > MAX_JSON_CHECKPOINT_BYTES:
        raise ValueError("Invalid JSON checkpoint byte length")
    try:
        doc = json.loads(
            raw, object_pairs_hook=_unique_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Malformed JSON checkpoint") from exc
    _keys(doc, {"format", "version", "sha256", "data"})
    if doc["format"] != _FORMAT or type(doc["version"]) is not int or doc["version"] != 1:
        raise ValueError("Unsupported checkpoint format/version")
    payload = _keys(doc["data"], {"requests", "seen"})
    if type(payload["requests"]) is not list or type(payload["seen"]) is not list:
        raise ValueError("Malformed checkpoint collections")
    # Limit pathological raw documents before re-serializing for checksum
    # verification. Typed objects receive a second, tighter limit at decode.
    _check_untrusted_json_limits(payload, _Budget())
    digest = doc["sha256"]
    if type(digest) is not str or len(digest) != 64 or hashlib.sha256(_canonical(payload)).hexdigest() != digest:
        raise ValueError("Checkpoint integrity digest does not match")
    budget = _Budget()
    from scrapling.spiders.checkpoint import CheckpointData
    from scrapling.spiders.request import Request
    requests = []
    for item in payload["requests"]:
        state = _unpack(item, budget)
        if type(state) is not dict:
            raise ValueError("Checkpoint request is not a mapping")
        _validate_request_state(state)
        request = Request(
            state["url"], sid=state["sid"], priority=state["priority"],
            dont_filter=state["dont_filter"], meta=state["meta"],
            _retry_count=state["_retry_count"],
        )
        request._session_kwargs = state["_session_kwargs"]
        request._fp = state["_fp"]
        if state["_callback_name"] is not None:
            request._callback_name = state["_callback_name"]
        requests.append(request)
    seen = set()
    for item in payload["seen"]:
        entry = _unpack(item, budget)
        if type(entry) not in (str, bytes) or entry in seen:
            raise ValueError("Invalid or duplicate checkpoint fingerprint")
        seen.add(entry)
    return CheckpointData(requests=requests, seen=seen)
