#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <job_id>" >&2
  exit 1
fi

job_id="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

job_file="$repo_root/workspace/jobs/$job_id.json"
if [[ ! -f "$job_file" ]]; then
  echo "missing $job_file; run eval/build_all.sh first." >&2
  exit 1
fi

job_fields="$(python3 - "$job_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    job = json.load(handle)
paths = job.get("paths", {})
fields = [
    job.get("primitive_type", ""),
    job.get("fuzzer_source", ""),
    paths.get("generated_config", ""),
    paths.get("build_dir", ""),
    paths.get("result_dir", ""),
    job.get("pair_id", ""),
]
print("\t".join(fields))
PY
)"
IFS=$'\t' read -r primitive_type fuzzer_source generated_config_rel build_dir_rel result_dir_rel pair_id <<<"$job_fields"

if [[ "$primitive_type" != "kem" && "$primitive_type" != "sig" ]]; then
  echo "build_one.sh supports generated kem and sig jobs; '$job_id' uses primitive '$primitive_type'." >&2
  exit 1
fi

build_dir="$repo_root/$build_dir_rel"
mkdir -p "$build_dir" "$repo_root/$result_dir_rel"

cxx_bin="${CXX:-$(command -v clang++ || command -v c++)}"
if [[ -z "$cxx_bin" ]]; then
  echo "missing C++ compiler." >&2
  exit 1
fi

deps=(
  src/adapters/status.cc
  src/adapters/liboqs/kem_adapter.cc
  src/adapters/liboqs/sig_adapter.cc
  src/adapters/pqclean/kem_adapter.cc
  src/adapters/pqclean/sig_adapter.cc
  src/mutators/envelope.cc
  src/mutators/ml_kem_layout.cc
  src/mutators/ml_kem_mutator.cc
  src/mutators/ml_dsa_layout.cc
  src/mutators/ml_dsa_mutator.cc
  src/mutators/slh_dsa_layout.cc
  src/mutators/slh_dsa_mutator.cc
  src/oracles/expected_relation.cc
  src/oracles/oracle_spec.cc
  src/oracles/oracle_spec_loader.cc
  src/oracles/oracle_executor.cc
  src/triage/finding_writer.cc
)

"$cxx_bin" -std=c++17 -O1 -g -Isrc -fsanitize=fuzzer,address,undefined \
  -DPQCFUZZ_JOB_ID="\"$job_id\"" \
  -DPQCFUZZ_PAIR_ID="\"$pair_id\"" \
  -DPQCFUZZ_RESULT_DIR="\"$result_dir_rel\"" \
  -DPQCFUZZ_GENERATED_CONFIG_PATH="\"$generated_config_rel\"" \
  "$fuzzer_source" "${deps[@]}" -o "$build_dir/fuzzer"

echo "built $build_dir_rel/fuzzer"
