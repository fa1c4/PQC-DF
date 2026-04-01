#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

find "$repo_root/workspace/build" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec rm -rf {} +
find "$repo_root/workspace/runs" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec rm -rf {} +
find "$repo_root/workspace/results" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec rm -rf {} +
find "$repo_root/workspace/crashes" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec rm -rf {} +
find "$repo_root/workspace/tmp" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec rm -rf {} +

echo "Workspace cleaned."

