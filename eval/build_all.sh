#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 differential_fuzzer/diff_fuzzer.py

python3 - <<'PY'
import json
from pathlib import Path

jobs = json.loads(Path("differential_fuzzer/data/fuzzer_jobs.json").read_text())
for job in jobs:
    print(job["job_id"])
PY

echo "Build orchestration is scaffolded, but native project compilation is not implemented yet."

