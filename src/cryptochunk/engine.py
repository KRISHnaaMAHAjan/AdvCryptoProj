"""Authenticated file chunking, local-node placement, and recovery logic."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import time
from pathlib import Path
from typing import Any

from .erasure import encode, decode

MANIFEST_NAME = "manifest.json"
KEY_NAME = "manifest.key"
DATA_SHARDS = 4
TOTAL_SHARDS = 6


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_key(root: Path, create: bool = False) -> bytes:
    path = root / KEY_NAME
    if path.exists():
        key = path.read_bytes()
        if len(key) < 32:
            raise ValueError(f"key file {path} is too short")
        return key
    if not create:
        raise FileNotFoundError(f"missing manifest key: {path}")
    root.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _sign_manifest(manifest: dict[str, Any], key: bytes) -> str:
    unsigned = {k: v for k, v in manifest.items() if k != "hmac_sha256"}
    return hmac.new(key, _canonical_json(unsigned), hashlib.sha256).hexdigest()


def verify_manifest(manifest: dict[str, Any], key: bytes) -> None:
    supplied = manifest.get("hmac_sha256", "")
    expected = _sign_manifest(manifest, key)
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("manifest authentication failed; metadata may have been modified")


def _node_dir(root: Path, node_index: int) -> Path:
    return root / f"node-{node_index + 1:02d}"


def store_file(source: str | Path, storage_root: str | Path, chunk_size: int = 262144) -> dict[str, Any]:
    """Split a file into logical chunks, erasure-code each chunk, and place shards."""
    source_path, root = Path(source), Path(storage_root)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    root.mkdir(parents=True, exist_ok=True)
    key = _load_key(root, create=True)
    file_bytes = source_path.read_bytes()
    file_id = secrets.token_hex(8)
    started = time.perf_counter()

    for index in range(TOTAL_SHARDS):
        node = _node_dir(root, index)
        node.mkdir(parents=True, exist_ok=True)
        # This demo owns the storage root; clear prior objects to avoid stale shards.
        for old in node.glob("*.shard"):
            old.unlink()

    chunks = [file_bytes[i:i + chunk_size] for i in range(0, len(file_bytes), chunk_size)]
    if not chunks:
        chunks = [b""]
    chunk_records: list[dict[str, Any]] = []
    shard_bytes_total = 0
    for chunk_index, chunk in enumerate(chunks):
        shards = encode(chunk)
        records = []
        for shard_index, shard in enumerate(shards):
            filename = f"{file_id}-chunk-{chunk_index:06d}-shard-{shard_index}.shard"
            path = _node_dir(root, shard_index) / filename
            path.write_bytes(shard)
            records.append({
                "index": shard_index,
                "node": f"node-{shard_index + 1:02d}",
                "path": str(path.relative_to(root)),
                "size": len(shard),
                "sha256": sha256(shard),
            })
            shard_bytes_total += len(shard)
        chunk_records.append({
            "index": chunk_index,
            "original_size": len(chunk),
            "original_sha256": sha256(chunk),
            "shards": records,
        })

    manifest: dict[str, Any] = {
        "format": "cryptochunk-manifest-v1",
        "file_id": file_id,
        "source_name": source_path.name,
        "original_size": len(file_bytes),
        "original_sha256": sha256(file_bytes),
        "chunk_size": chunk_size,
        "data_shards": DATA_SHARDS,
        "total_shards": TOTAL_SHARDS,
        "created_unix": int(time.time()),
        "chunks": chunk_records,
    }
    manifest["hmac_sha256"] = _sign_manifest(manifest, key)
    (root / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "file_id": file_id,
        "source_name": source_path.name,
        "original_size": len(file_bytes),
        "logical_chunks": len(chunks),
        "shards_written": len(chunks) * TOTAL_SHARDS,
        "stored_shard_bytes": shard_bytes_total,
        "raw_overhead_ratio": (shard_bytes_total / len(file_bytes)) if file_bytes else 0.0,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
        "manifest": str(root / MANIFEST_NAME),
    }


def _read_manifest(root: Path, key: bytes) -> dict[str, Any]:
    path = root / MANIFEST_NAME
    manifest = json.loads(path.read_text(encoding="utf-8"))
    verify_manifest(manifest, key)
    if manifest.get("format") != "cryptochunk-manifest-v1":
        raise ValueError("unsupported manifest format")
    if manifest.get("data_shards") != DATA_SHARDS or manifest.get("total_shards") != TOTAL_SHARDS:
        raise ValueError("unsupported erasure-code parameters")
    return manifest


def restore_file(storage_root: str | Path, destination: str | Path) -> dict[str, Any]:
    """Verify every shard, reconstruct missing/corrupt shards, then verify output."""
    root, output = Path(storage_root), Path(destination)
    key = _load_key(root)
    manifest = _read_manifest(root, key)
    started = time.perf_counter()
    rebuilt_chunks: list[bytes] = []
    missing_or_corrupt: list[str] = []
    repaired_shards = 0

    for chunk in manifest["chunks"]:
        valid: dict[int, bytes] = {}
        bad_records = []
        for record in chunk["shards"]:
            shard_path = root / record["path"]
            try:
                shard = shard_path.read_bytes()
                if len(shard) != record["size"] or not hmac.compare_digest(sha256(shard), record["sha256"]):
                    raise ValueError("checksum mismatch")
                valid[record["index"]] = shard
            except (OSError, ValueError):
                missing_or_corrupt.append(record["path"])
                bad_records.append(record)
        if len(valid) < DATA_SHARDS:
            raise ValueError(
                f"chunk {chunk['index']} has only {len(valid)} valid shards; "
                f"at least {DATA_SHARDS} are required"
            )
        decoded = decode(valid)[:chunk["original_size"]]
        if not hmac.compare_digest(sha256(decoded), chunk["original_sha256"]):
            raise ValueError(f"reconstructed chunk {chunk['index']} failed its original-data SHA-256 check")
        rebuilt_chunks.append(decoded)

        if bad_records:
            all_shards = encode(decoded)
            for record in bad_records:
                repaired = all_shards[record["index"]]
                target = root / record["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(repaired)
                repaired_shards += 1

    restored = b"".join(rebuilt_chunks)
    if len(restored) != manifest["original_size"]:
        raise ValueError("restored file length does not match authenticated manifest")
    if not hmac.compare_digest(sha256(restored), manifest["original_sha256"]):
        raise ValueError("restored file SHA-256 mismatch")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(restored)
    return {
        "output": str(output),
        "restored_size": len(restored),
        "sha256": sha256(restored),
        "verified": True,
        "unavailable_or_corrupt_shards": missing_or_corrupt,
        "repaired_shards": repaired_shards,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
    }


def simulate_fault(storage_root: str | Path, chunk_index: int, shard_index: int, action: str) -> str:
    """Demo helper: remove a shard or flip one byte to model an untrusted node."""
    if action not in {"remove", "corrupt"}:
        raise ValueError("action must be 'remove' or 'corrupt'")
    root = Path(storage_root)
    key = _load_key(root)
    manifest = _read_manifest(root, key)
    try:
        record = manifest["chunks"][chunk_index]["shards"][shard_index]
    except IndexError as exc:
        raise ValueError("chunk or shard index is out of range") from exc
    path = root / record["path"]
    if action == "remove":
        path.unlink(missing_ok=True)
    else:
        data = bytearray(path.read_bytes())
        if not data:
            data = bytearray(b"\x00")
        data[0] ^= 0x80
        path.write_bytes(data)
    return str(path)
