"""Generate reproducible local benchmark results for the project report."""
from __future__ import annotations
import csv
import hashlib
import json
import platform
import tempfile
import time
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cryptochunk.engine import store_file, restore_file, simulate_fault

SIZES = [1024, 65536, 1048576, 4194304]
OUT = Path(__file__).resolve().parents[1] / "artifacts" / "benchmark.csv"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="cryptochunk-bench-") as temp:
        root = Path(temp)
        for size in SIZES:
            source = root / f"input-{size}.bin"
            source.write_bytes(bytes((i * 37 + 11) % 256 for i in range(size)))
            storage = root / f"storage-{size}"
            t0 = time.perf_counter()
            stored = store_file(source, storage, chunk_size=262144)
            store_elapsed = time.perf_counter() - t0
            simulate_fault(storage, 0, 2, "corrupt")
            simulate_fault(storage, 0, 5, "remove")
            restored = root / f"restored-{size}.bin"
            t1 = time.perf_counter()
            result = restore_file(storage, restored)
            restore_elapsed = time.perf_counter() - t1
            rows.append({
                "python": platform.python_version(), "platform": platform.platform(),
                "input_bytes": size, "logical_chunks": stored["logical_chunks"],
                "stored_shard_bytes": stored["stored_shard_bytes"],
                "overhead_percent": round((stored["stored_shard_bytes"] / max(size, 1) - 1) * 100, 2),
                "store_seconds": round(store_elapsed, 6), "restore_seconds": round(restore_elapsed, 6),
                "fault_tolerance_check": "PASS" if result["verified"] and restored.read_bytes() == source.read_bytes() else "FAIL",
                "sha256": hashlib.sha256(restored.read_bytes()).hexdigest(),
            })
    with OUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({"output": str(OUT), "rows": rows}, indent=2))

if __name__ == "__main__":
    main()
