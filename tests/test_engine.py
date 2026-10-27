import hashlib
import json
from pathlib import Path
import pytest
from cryptochunk.engine import store_file, restore_file, simulate_fault


def test_roundtrip_and_repair(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(bytes(range(256)) * 400 + b"tail")
    storage = tmp_path / "storage"
    report = store_file(source, storage, chunk_size=8192)
    assert report["shards_written"] == report["logical_chunks"] * 6
    simulate_fault(storage, 0, 1, "corrupt")
    simulate_fault(storage, 0, 4, "remove")
    restored = tmp_path / "restored.bin"
    result = restore_file(storage, restored)
    assert result["verified"] is True
    assert restored.read_bytes() == source.read_bytes()
    assert result["repaired_shards"] == 2


def test_manifest_tampering_is_rejected(tmp_path: Path):
    source = tmp_path / "source.txt"
    source.write_text("integrity matters")
    storage = tmp_path / "storage"
    store_file(source, storage)
    manifest_path = storage / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["original_size"] += 1
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="manifest authentication failed"):
        restore_file(storage, tmp_path / "out.txt")


def test_more_than_two_shard_losses_fails(tmp_path: Path):
    source = tmp_path / "source.txt"
    source.write_bytes(b"abc" * 100)
    storage = tmp_path / "storage"
    store_file(source, storage)
    for shard in (0, 1, 2):
        simulate_fault(storage, 0, shard, "remove")
    with pytest.raises(ValueError, match="only 3 valid shards"):
        restore_file(storage, tmp_path / "out.txt")
