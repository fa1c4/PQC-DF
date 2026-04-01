#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <job_id> <input_file>" >&2
  exit 1
fi

echo "replay_one.sh is scaffolded for job '$1' with input '$2', but replay is not implemented yet."

