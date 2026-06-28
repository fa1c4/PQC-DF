#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 src/pairing/validate_pair_alg.py --pair-alg src/config/pair_alg.default.json
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.default.json --algorithm-family ML-KEM
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.default.json --algorithm-family ML-DSA
python3 src/jobs/generate_jobs.py --pair-alg src/config/pair_alg.default.json --algorithm-family SLH-DSA

python3 - <<'PY'
import json
from pathlib import Path

for path in sorted(Path("workspace/jobs").glob("job_*.json")):
    job = json.loads(path.read_text())
    print(job["job_id"])
PY

echo "Job generation complete. Use eval/build_one.sh <job_id> for the native fuzzer build path."
