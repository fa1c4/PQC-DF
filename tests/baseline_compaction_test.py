import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPACTOR = ROOT / "scripts" / "compact_baseline_results.py"


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def touch(path: Path, contents: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def run_compactor(
    workspace: Path,
    baseline: str,
    version: str = "0.14.0",
    mode: str = "compact",
    skip_reason: str = "",
) -> None:
    cmd = [
        sys.executable,
        str(COMPACTOR),
        "--workspace-root",
        str(workspace),
        "--baseline",
        baseline,
        "--version",
        version,
        "--mode",
        mode,
    ]
    if skip_reason:
        cmd.extend(["--skip-reason", skip_reason])
    subprocess.run(
        cmd,
        cwd=ROOT,
        check=True,
    )


def load_manifest(workspace: Path, baseline: str) -> dict:
    manifest_path = workspace / baseline / "compaction_manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def test_libfuzzer_compaction_keeps_summaries_logs_and_crashes(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "libFuzzer"
    run_root = root / "targets-run" / "liboqs-0.14.0"

    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o")
    write_json(run_root / "summary.json", {"baseline": "libFuzzer", "status": 0})
    write_json(run_root / "kem" / "summary.json", {"target": "kem", "status": 0})
    write_json(run_root / "sig" / "summary.json", {"target": "sig", "status": 0})
    touch(run_root / "kem" / "logs" / "full.log", "log")
    touch(run_root / "kem" / "corpus" / "seed", "seed")
    touch(run_root / "kem" / "artifacts" / "unused", "artifact")
    touch(run_root / "kem" / "crashes" / "crash-a", "crash")
    touch(run_root / "kem" / "crashes" / "timeout-b", "timeout")
    touch(run_root / "kem" / "crashes" / "nested" / "crash-nested", "nested-crash")
    touch(run_root / "kem" / "crashes" / "nested" / "notes.txt", "remove-me")
    touch(run_root / "sig" / "crashes" / "oom-c", "oom")

    run_compactor(workspace, "libFuzzer")

    assert not (root / "targets-build").exists()
    assert not (run_root / "kem" / "corpus").exists()
    assert not (run_root / "kem" / "artifacts").exists()
    assert (run_root / "summary.json").is_file()
    assert (run_root / "kem" / "summary.json").is_file()
    assert (run_root / "kem" / "logs" / "full.log").is_file()
    assert (run_root / "kem" / "crashes" / "crash-a").is_file()
    assert (run_root / "kem" / "crashes" / "timeout-b").is_file()
    assert (run_root / "kem" / "crashes" / "nested" / "crash-nested").is_file()
    assert not (run_root / "kem" / "crashes" / "nested" / "notes.txt").exists()
    assert (run_root / "sig" / "crashes" / "oom-c").is_file()

    manifest = load_manifest(workspace, "libFuzzer")
    assert manifest["status"] == "completed"
    assert manifest["build_retained"] is False
    assert manifest["corpus_retained"] is False
    assert manifest["retained_artifact_counts"]["crash"] == 2
    assert manifest["retained_artifact_counts"]["timeout"] == 1
    assert manifest["retained_artifact_counts"]["oom"] == 1

    summary = json.loads((run_root / "summary.json").read_text(encoding="utf-8"))
    assert summary["result_save_mode"] == "compact"
    assert summary["compacted"] is True


def test_cryptofuzz_and_clfuzz_compaction_use_single_run_layout(tmp_path: Path) -> None:
    for baseline in ("cryptofuzz", "CLFuzz"):
        workspace = tmp_path / baseline / "workspace"
        root = workspace / baseline
        run_root = root / "targets-run" / "liboqs-0.8.0"

        touch(root / "targets-build" / "liboqs-0.8.0" / "object.o")
        write_json(run_root / "summary.json", {"baseline": baseline, "status": 0})
        touch(run_root / "logs" / "full.log", "log")
        touch(run_root / "corpus" / "seed", "seed")
        touch(run_root / "artifacts" / "unused", "artifact")
        touch(run_root / "crashes" / "leak-a", "leak")

        run_compactor(workspace, baseline, version="0.8.0")

        assert not (root / "targets-build").exists()
        assert not (run_root / "corpus").exists()
        assert not (run_root / "artifacts").exists()
        assert (run_root / "summary.json").is_file()
        assert (run_root / "logs" / "full.log").is_file()
        assert (run_root / "crashes" / "leak-a").is_file()

        manifest = load_manifest(workspace, baseline)
        assert manifest["retained_artifact_counts"]["leak"] == 1
        assert manifest["build_retained"] is False


def test_cryptotesting_compaction_copies_afl_crashes_and_hangs(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "cryptoTesting"
    build_target = root / "targets-build" / "ches_liboqs"
    run_root = root / "targets-run"

    touch(build_target / "alg1" / "fuzzoutputs" / "default" / "crashes" / "id:000000", "crash")
    touch(build_target / "alg1" / "fuzzoutputs" / "default" / "crashes" / "README.txt", "readme")
    touch(build_target / "alg1" / "fuzzoutputs" / "default" / "hangs" / "id:000001", "hang")
    touch(run_root / "reports" / "crash_report_ches_liboqs_python.xlsx", "report")
    touch(run_root / "logs" / "ches_liboqs.functional.log", "log")

    run_compactor(workspace, "cryptoTesting", version="0.14.0")

    artifact_root = run_root / "artifacts" / "ches_liboqs" / "alg1" / "fuzzoutputs" / "default"
    assert not (root / "targets-build").exists()
    assert (run_root / "reports" / "crash_report_ches_liboqs_python.xlsx").is_file()
    assert (run_root / "logs" / "ches_liboqs.functional.log").is_file()
    assert (artifact_root / "crashes" / "id:000000").read_text(encoding="utf-8") == "crash"
    assert (artifact_root / "hangs" / "id:000001").read_text(encoding="utf-8") == "hang"
    assert not (artifact_root / "crashes" / "README.txt").exists()

    manifest = load_manifest(workspace, "cryptoTesting")
    assert manifest["retained_artifact_counts"]["crash"] == 1
    assert manifest["retained_artifact_counts"]["hang"] == 1

    summary = json.loads((run_root / "summary.json").read_text(encoding="utf-8"))
    assert summary["baseline"] == "cryptoTesting"
    assert summary["target"] == "ches_liboqs"
    assert summary["compacted"] is True


def test_all_mode_leaves_tree_untouched(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "cryptofuzz"
    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o")
    touch(root / "targets-run" / "liboqs-0.14.0" / "corpus" / "seed")

    run_compactor(workspace, "cryptofuzz", mode="all")

    assert (root / "targets-build" / "liboqs-0.14.0" / "object.o").is_file()
    assert (root / "targets-run" / "liboqs-0.14.0" / "corpus" / "seed").is_file()
    assert not (root / "compaction_manifest.json").exists()


def test_skipped_compaction_writes_non_compacted_manifest_without_deleting(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "libFuzzer"
    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o")

    run_compactor(workspace, "libFuzzer", skip_reason="campaign did not reach result-producing phase")

    assert (root / "targets-build" / "liboqs-0.14.0" / "object.o").is_file()
    manifest = load_manifest(workspace, "libFuzzer")
    assert manifest["status"] == "skipped"
    assert manifest["compacted"] is False
    assert manifest["reason"] == "campaign did not reach result-producing phase"
    assert manifest["removed_paths"] == []
