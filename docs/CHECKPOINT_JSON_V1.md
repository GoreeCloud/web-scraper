# GoreeCloud Web Scraper — opt-in JSON checkpoint v1 (development)

**Status:** experimental, explicitly opted-in; not a blanket permission to resume third-party crawls or a production backup guarantee. The upstream-attributed Scrapling integration remains available and its **default** `checkpoint.pkl` persistence remains unchanged.

## Choosing an on-disk format

The new non-executable, versioned format is selected when constructing a spider:

```python
spider = MySpider(crawldir="/private/mycrawl", checkpoint_format="json_v1")
result = spider.start()
```

This stores **`checkpoint.json`**, not `checkpoint.pkl`. It passes the selected format through the existing Spider → CrawlerEngine → CheckpointManager path for `start()` and `stream()` operations. Plain `MySpider(crawldir=...)` continues to use the inherited legacy `checkpoint.pkl` format and accepts existing downstream restricted-pickle files.

The two formats are **distinct**: selecting JSON does not silently deserialize, migrate, replace, delete, or automatically resume a legacy pickle. Switching formats without separately migrating a stopped crawl may cause the crawler to begin from its initial requests rather than the old checkpoint. Preserve the original crawl directory, and test a small owned crawl before adopting this option. **Never select two different formats concurrently in a shared live crawl directory.**

## Supported data, safety and limits

JSON v1 stores an explicit document format/version, a deterministic canonical payload and SHA-256 integrity digest. The format accepts ordinary `Request` objects, string/bytes seen fingerprints, URL/session/priority/filter/retry fields, ordinary callback-name identifiers, and recursively bounded inert values in request metadata and HTTP kwargs: `None`, `bool`, `int`, finite `float`, `str`, `bytes`, `list`, `tuple`, and `dict` with **string keys**. Bytes and tuples have explicit tagged representations. It rejects arbitrary Python objects/functions, unknown fields, duplicate JSON keys, invalid Base64, excessive nesting/nodes/atoms and invalid integrity digests; unsupported custom objects are **not silently coerced**. Derived cached URL domains are recomputed rather than serialized.

The manager keeps the existing 64 MiB checkpoint file ceiling and private atomic replacement; JSON nested values are capped at 16 levels, 200,000 decoded nodes and 2 MiB individual string/byte atoms. This is a validation budget, not comprehensive resource/CPU isolation; an abusive local source can still exhaust resources outside these checks. A SHA-256 digest detects **accidental corruption**, not tampering by an adversary who can rewrite the whole document. No encryption, confidentiality, digital signature or runtime authorization is provided by this codec.

Checkpoints can hold sensitive URL paths, request headers, cookies, form inputs and personal metadata. Restrict directory permissions, protect backups, avoid copying private checkpoints into tickets/CI logs or public repositories, and apply GoreeShield collection, sharing, consent and retention requirements.

## Offline migration of an existing trusted local checkpoint

Before migration, **stop** the original crawl and back up the entire crawl directory. Only consider migrating a checkpoint created by the owner in a trusted, private directory. The inherited restricted pickle reader **still uses pickle** and is not a safe parser for stranger-provided bytes. The codec does **not** automatically load pickle in JSON mode.

For an offline, previously trusted local checkpoint, use a reviewed one-time script that reads the old state with `CheckpointManager(...)`, verifies it returned a non-null `CheckpointData`, and writes the separate file with `CheckpointManager(..., checkpoint_format="json_v1")`. Verify restored requests, fingerprints, callback names and any custom metadata **without contacting external targets**. Compare old checkpoint SHA-256 before/after; preserve the original `checkpoint.pkl` for rollback. If the selected JSON file already exists, preserve it rather than overwriting it as part of migration.

Do not migrate while a spider is running, do not treat the conversion as verification of unknown downloaded pickle files, and do not delete the legacy file until a subsequent explicit recovery decision. If a Request contains custom Python or unsupported payload types, JSON v1 deliberately fails; preserve your old format and design an explicit, tested adapter before migrating.

## Release limitations

This sub-feature does **not** close [functional/privacy gate #2](https://github.com/GoreeCloud/web-scraper/issues/2) or [security/supply-chain gate #3](https://github.com/GoreeCloud/web-scraper/issues/3). Remaining work includes cross-platform/real crawler pause–resume acceptance with complex state, backed-up migration/rollback for arbitrary inherited data, filesystem ownership/hardlink and resource-threat review, OS egress and browser/CDP isolation, GoreeShield user consent/robots/site policy/retention enforcement, Wardveil security review, supply-chain source license/SBOM evidence, production Identity/TLS, and signed Stable release decisions. No package is published or service deployed by this change.
