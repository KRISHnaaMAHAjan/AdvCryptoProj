#!/usr/bin/env bash
set -euo pipefail
python -m cryptochunk.cli store examples/sample.txt --storage demo-storage --chunk-size 32
python -m cryptochunk.cli fault --storage demo-storage --chunk 0 --shard 1 --action corrupt
python -m cryptochunk.cli fault --storage demo-storage --chunk 0 --shard 4 --action remove
python -m cryptochunk.cli restore --storage demo-storage --output restored.txt
cmp examples/sample.txt restored.txt
printf 'Demo complete: restored file matches source.\n'
