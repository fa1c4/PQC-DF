#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <job_id>" >&2
  exit 1
fi

echo "run_one.sh is scaffolded for job '$1', but execution is not implemented yet."

