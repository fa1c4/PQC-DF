#!/usr/bin/env python3
"""Compact baseline fuzzer result trees after an eval campaign."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ARTIFACT_PREFIXES = ("crash-", "timeout-", "leak-", "oom-")
COUNT_KEYS = ("crash", "timeout", "leak", "oom", "hang")
CRYPTOTESTING_TARGETS = {
    "0.14.0": "ches_liboqs",
    "0.8.0": "cur_liboqs",
    "0.4.0": "mid_liboqs",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: Path) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:
        return str(path)


def rel_to(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return rel(path)


def is_within(path: Path, root: Path) -> bool:
    path_abs = os.path.abspath(path)
    root_abs = os.path.abspath(root)
    try:
        return os.path.commonpath([path_abs, root_abs]) == root_abs
    except ValueError:
        return False


def path_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file() or path.is_symlink():
        try:
            return path.stat().st_size
        except OSError:
            return 0

    total = 0
    for child in path.rglob("*"):
        if not child.is_file() and not child.is_symlink():
            continue
        try:
            total += child.stat().st_size
        except OSError:
            pass
    return total


def count_prefix_artifact(path: Path, counts: dict[str, int]) -> bool:
    name = path.name
    for prefix in ARTIFACT_PREFIXES:
        if name.startswith(prefix):
            counts[prefix[:-1]] += 1
            return True
    return False


class Compactor:
    def __init__(self, workspace_root: Path, baseline: str, version: str) -> None:
        self.workspace_root = workspace_root
        self.baseline = baseline
        self.version = version
        self.baseline_root = workspace_root / baseline
        self.build_root = self.baseline_root / "targets-build"
        self.run_root = self.baseline_root / "targets-run"
        self.manifest_path = self.baseline_root / "compaction_manifest.json"
        self.retained_paths: set[str] = set()
        self.removed_paths: list[str] = []
        self.removed_bytes_estimate = 0
        self.retained_artifact_counts = {key: 0 for key in COUNT_KEYS}

    def require_safe_path(self, path: Path) -> None:
        if not is_within(path, self.baseline_root):
            raise RuntimeError(f"refusing to modify path outside baseline workspace: {path}")

    def retain(self, path: Path) -> None:
        if path.exists():
            self.retained_paths.add(rel(path))

    def retain_tree_files(self, root: Path) -> None:
        if not root.is_dir():
            return
        for path in sorted(root.rglob("*")):
            if path.is_file():
                self.retain(path)

    def remove_path(self, path: Path) -> None:
        if not path.exists():
            return
        self.require_safe_path(path)
        self.removed_bytes_estimate += path_size(path)
        self.removed_paths.append(rel(path))
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()

    def remove_children_except_prefix_artifacts(self, root: Path) -> None:
        if not root.is_dir():
            return
        self.require_safe_path(root)
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_file() and count_prefix_artifact(path, self.retained_artifact_counts):
                self.retain(path)
                continue
            if path.is_dir():
                if not any(path.iterdir()):
                    self.remove_path(path)
                continue
            self.remove_path(path)

    def compact_libfuzzer(self) -> None:
        version_run_root = self.run_root / f"liboqs-{self.version}"
        for summary in sorted(version_run_root.rglob("summary.json")):
            self.retain(summary)
        for logs_dir in sorted(version_run_root.rglob("logs")):
            self.retain_tree_files(logs_dir)
        for target in ("kem", "sig"):
            target_root = version_run_root / target
            self.remove_children_except_prefix_artifacts(target_root / "crashes")
            self.remove_path(target_root / "corpus")
            self.remove_path(target_root / "artifacts")
        self.remove_path(self.build_root)

    def compact_single_libfuzzer_style(self) -> None:
        version_run_root = self.run_root / f"liboqs-{self.version}"
        self.retain(version_run_root / "summary.json")
        self.retain_tree_files(version_run_root / "logs")
        self.remove_children_except_prefix_artifacts(version_run_root / "crashes")
        self.remove_path(version_run_root / "corpus")
        self.remove_path(version_run_root / "artifacts")
        self.remove_path(self.build_root)

    def crypto_testing_target(self) -> str:
        return CRYPTOTESTING_TARGETS.get(self.version, f"liboqs-{self.version}")

    def copy_crypto_testing_artifacts(self) -> None:
        target = self.crypto_testing_target()
        build_target = self.build_root / target
        artifact_root = self.run_root / "artifacts" / target
        if not build_target.is_dir():
            return

        for kind in ("crashes", "hangs"):
            for source_dir in sorted(build_target.rglob(f"fuzzoutputs/default/{kind}")):
                if not source_dir.is_dir():
                    continue
                for source in sorted(source_dir.iterdir()):
                    if not source.is_file() or source.name == "README.txt":
                        continue
                    relative = source.relative_to(build_target)
                    destination = artifact_root / relative
                    self.require_safe_path(destination)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)
                    self.retain(destination)
                    if kind == "hangs":
                        self.retained_artifact_counts["hang"] += 1
                    else:
                        self.retained_artifact_counts["crash"] += 1

    def compact_crypto_testing(self) -> None:
        self.retain_tree_files(self.run_root / "reports")
        self.retain_tree_files(self.run_root / "logs")
        self.copy_crypto_testing_artifacts()
        self.remove_path(self.build_root)

    def compact(self) -> dict[str, Any]:
        if self.baseline == "libFuzzer":
            self.compact_libfuzzer()
        elif self.baseline in {"cryptofuzz", "CLFuzz"}:
            self.compact_single_libfuzzer_style()
        elif self.baseline == "cryptoTesting":
            self.compact_crypto_testing()
        else:
            raise RuntimeError(f"unsupported baseline: {self.baseline}")

        manifest = {
            "baseline": self.baseline,
            "version": self.version,
            "mode": "compact",
            "generated_at": utc_now(),
            "status": "completed",
            "compacted": True,
            "workspace_root": rel(self.workspace_root),
            "baseline_root": rel(self.baseline_root),
            "retained_paths": [],
            "removed_paths": self.removed_paths,
            "retained_artifact_counts": dict(self.retained_artifact_counts),
            "removed_bytes_estimate": self.removed_bytes_estimate,
            "build_retained": self.build_root.exists(),
            "corpus_retained": any(path.name == "corpus" for path in self.run_root.rglob("corpus"))
            if self.run_root.is_dir()
            else False,
        }
        self.update_summaries(manifest)
        self.retained_paths.add(rel(self.manifest_path))
        manifest["retained_paths"] = sorted(self.retained_paths)
        self.write_manifest(manifest)
        return manifest

    def write_manifest(self, manifest: dict[str, Any]) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with self.manifest_path.open("w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
            f.write("\n")

    def write_skipped_manifest(self, reason: str) -> dict[str, Any]:
        manifest = {
            "baseline": self.baseline,
            "version": self.version,
            "mode": "compact",
            "generated_at": utc_now(),
            "status": "skipped",
            "reason": reason,
            "compacted": False,
            "workspace_root": rel(self.workspace_root),
            "baseline_root": rel(self.baseline_root),
            "retained_paths": [rel(self.manifest_path)],
            "removed_paths": [],
            "retained_artifact_counts": dict(self.retained_artifact_counts),
            "removed_bytes_estimate": 0,
            "build_retained": self.build_root.exists(),
            "corpus_retained": any(path.name == "corpus" for path in self.run_root.rglob("corpus"))
            if self.run_root.is_dir()
            else False,
        }
        self.write_manifest(manifest)
        return manifest

    def summary_updates(self, manifest: dict[str, Any]) -> dict[str, Any]:
        return {
            "result_save_mode": "compact",
            "compacted": True,
            "compaction_manifest": rel(self.manifest_path),
            "build_retained": manifest["build_retained"],
            "corpus_retained": manifest["corpus_retained"],
            "retained_artifact_counts": manifest["retained_artifact_counts"],
        }

    def update_summary_file(self, path: Path, updates: dict[str, Any]) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        data.update(updates)
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        self.retain(path)

    def create_crypto_testing_summary(self, manifest: dict[str, Any], updates: dict[str, Any]) -> None:
        summary_path = self.run_root / "summary.json"
        if summary_path.exists():
            return
        reports_dir = self.run_root / "reports"
        logs_dir = self.run_root / "logs"
        artifacts_dir = self.run_root / "artifacts" / self.crypto_testing_target()
        data: dict[str, Any] = {
            "baseline": "cryptoTesting",
            "version": self.version,
            "target": self.crypto_testing_target(),
            "mode": "functional",
            "reports": sorted(rel(path) for path in reports_dir.glob("*") if path.is_file())
            if reports_dir.is_dir()
            else [],
            "logs": sorted(rel(path) for path in logs_dir.glob("*") if path.is_file())
            if logs_dir.is_dir()
            else [],
            "artifacts": sorted(rel(path) for path in artifacts_dir.rglob("*") if path.is_file())
            if artifacts_dir.is_dir()
            else [],
        }
        data.update(updates)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        self.retain(summary_path)

    def update_summaries(self, manifest: dict[str, Any]) -> None:
        updates = self.summary_updates(manifest)
        if self.baseline == "cryptoTesting":
            self.create_crypto_testing_summary(manifest, updates)
        for summary in sorted(self.run_root.rglob("summary.json")):
            self.update_summary_file(summary, updates)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", required=True, type=Path)
    parser.add_argument("--baseline", required=True, choices=["libFuzzer", "cryptofuzz", "CLFuzz", "cryptoTesting"])
    parser.add_argument("--version", required=True)
    parser.add_argument("--mode", required=True, choices=["compact", "all"])
    parser.add_argument("--skip-reason", default="", help="write a skipped manifest without deleting files")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    workspace_root = args.workspace_root.resolve()
    baseline_root = workspace_root / args.baseline

    if args.mode == "all":
        print(f"[baseline-compact] mode=all; leaving {baseline_root} unchanged")
        return 0

    compactor = Compactor(workspace_root, args.baseline, args.version)
    if args.skip_reason:
        manifest = compactor.write_skipped_manifest(args.skip_reason)
        print(compactor.manifest_path)
        print(f"[baseline-compact] skipped: {manifest['reason']}")
        return 0

    manifest = compactor.compact()
    print(compactor.manifest_path)
    print(
        "[baseline-compact] removed "
        f"{manifest['removed_bytes_estimate']} bytes from {len(manifest['removed_paths'])} paths"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
