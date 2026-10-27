"""Command-line interface for CryptoChunk."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .engine import store_file, restore_file, simulate_fault


def _print_result(result: dict) -> None:
    print(json.dumps(result, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="cryptochunk", description="Authenticated 4+2 erasure-coded file storage demo")
    commands = parser.add_subparsers(dest="command", required=True)
    store = commands.add_parser("store", help="chunk, encode, checksum, and store a file")
    store.add_argument("source", type=Path)
    store.add_argument("--storage", type=Path, required=True)
    store.add_argument("--chunk-size", type=int, default=262144, help="logical chunk size in bytes (default: 262144)")
    restore = commands.add_parser("restore", help="verify shards and reconstruct a file")
    restore.add_argument("--storage", type=Path, required=True)
    restore.add_argument("--output", type=Path, required=True)
    fault = commands.add_parser("fault", help="simulate a missing or modified shard")
    fault.add_argument("--storage", type=Path, required=True)
    fault.add_argument("--chunk", type=int, default=0)
    fault.add_argument("--shard", type=int, required=True, choices=range(6))
    fault.add_argument("--action", choices=("remove", "corrupt"), required=True)
    args = parser.parse_args()
    try:
        if args.command == "store":
            _print_result(store_file(args.source, args.storage, args.chunk_size))
        elif args.command == "restore":
            _print_result(restore_file(args.storage, args.output))
        else:
            print(f"Simulated {args.action}: {simulate_fault(args.storage, args.chunk, args.shard, args.action)}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

if __name__ == "__main__":
    main()
