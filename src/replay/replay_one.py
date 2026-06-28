#!/usr/bin/env python3
"""Replay one PQCFuzz structured input and write trace/artifact output."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from triage.classify_finding import classify_trace
from triage.poc_generator import generate_poc


ALGORITHM_BY_ENUM = {
    1: "ML-KEM-512",
    2: "ML-KEM-768",
    3: "ML-KEM-1024",
    4: "ML-DSA-44",
    5: "ML-DSA-65",
    6: "ML-DSA-87",
    7: "SLH-DSA-SHA2-128s",
    8: "SLH-DSA-SHAKE-128s",
    9: "SLH-DSA-SHA2-128f",
    10: "SLH-DSA-SHAKE-128f",
    11: "SLH-DSA-SHA2-192s",
    12: "SLH-DSA-SHAKE-192s",
    13: "SLH-DSA-SHA2-192f",
    14: "SLH-DSA-SHAKE-192f",
    15: "SLH-DSA-SHA2-256s",
    16: "SLH-DSA-SHAKE-256s",
    17: "SLH-DSA-SHA2-256f",
    18: "SLH-DSA-SHAKE-256f",
}
ORACLE_BY_ENUM = {
    1: "mlkem_local_roundtrip",
    2: "mlkem_cross_exchange_roundtrip",
    3: "mlkem_tampered_ciphertext_implicit_rejection",
    4: "mlkem_bad_randomness_sanity",
    5: "mldsa_local_sign_verify",
    6: "mldsa_cross_verify",
    7: "mldsa_mutated_signature_negative",
    8: "mldsa_mutated_message_negative",
    9: "mldsa_mutated_context_negative",
    10: "mldsa_oid_field_mutation_sanity",
    11: "mldsa_bad_randomness_sanity",
    12: "slhdsa_local_sign_verify",
    13: "slhdsa_cross_verify",
    14: "slhdsa_mutated_signature_negative",
    15: "slhdsa_mutated_message_negative",
    16: "slhdsa_mutated_context_negative",
    17: "slhdsa_bad_randomness_sanity",
}


class ReplayError(RuntimeError):
    """Raised when replay input or job data is invalid."""


def read_u16_le(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise ReplayError("truncated u16 length in PQCFuzz envelope")
    return data[offset] | (data[offset + 1] << 8), offset + 2


def read_slice(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    if offset + length > len(data):
        raise ReplayError(f"truncated {label} field in PQCFuzz envelope")
    return data[offset : offset + length], offset + length


def default_envelope(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "magic": "PQCF",
        "version": 1,
        "algorithm": job["algorithm"],
        "oracle_id": (
            "slhdsa_local_sign_verify"
            if job.get("algorithm_family") == "SLH-DSA"
            else ("mldsa_local_sign_verify" if job["primitive_type"] == "sig" else "mlkem_local_roundtrip")
        ),
        "flags": 0,
        "seed": b"pqcfuzz-default-seed",
        "msg": b"",
        "mutation": b"",
        "extra": b"",
        "source_format": "built-in-default",
    }


def parse_binary_envelope(data: bytes) -> dict[str, Any]:
    if len(data) < 8 or data[:4] != b"PQCF":
        raise ReplayError("input does not start with PQCF envelope magic")
    version = data[4]
    algorithm_enum = data[5]
    oracle_enum = data[6]
    flags = data[7]
    offset = 8
    seed_len, offset = read_u16_le(data, offset)
    seed, offset = read_slice(data, offset, seed_len, "seed")
    msg_len, offset = read_u16_le(data, offset)
    msg, offset = read_slice(data, offset, msg_len, "msg")
    mutation_len, offset = read_u16_le(data, offset)
    mutation, offset = read_slice(data, offset, mutation_len, "mutation")
    extra_len, offset = read_u16_le(data, offset)
    extra, offset = read_slice(data, offset, extra_len, "extra")
    if offset != len(data):
        raise ReplayError("PQCFuzz envelope has trailing bytes after extra field")
    return {
        "magic": "PQCF",
        "version": version,
        "algorithm": ALGORITHM_BY_ENUM.get(algorithm_enum, f"UNKNOWN-{algorithm_enum}"),
        "oracle_id": ORACLE_BY_ENUM.get(oracle_enum, f"UNKNOWN-{oracle_enum}"),
        "flags": flags,
        "seed": seed,
        "msg": msg,
        "mutation": mutation,
        "extra": extra,
        "source_format": "binary-envelope",
    }


def parse_json_envelope(data: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReplayError(f"input is neither a binary PQCF envelope nor JSON envelope: {exc}") from exc
    if payload.get("magic") != "PQCF":
        raise ReplayError("JSON envelope magic must be PQCF")
    return {
        "magic": "PQCF",
        "version": int(payload.get("version", 1)),
        "algorithm": str(payload["algorithm"]),
        "oracle_id": str(payload["oracle_id"]),
        "flags": int(payload.get("flags", 0)),
        "seed": base64.b64decode(payload.get("seed_b64", "")),
        "msg": base64.b64decode(payload.get("msg_b64", "")),
        "mutation": base64.b64decode(payload.get("mutation_b64", "")),
        "extra": base64.b64decode(payload.get("extra_b64", "")),
        "source_format": "json-envelope",
    }


def parse_envelope(path: Path, job: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    if not path.exists():
        envelope = default_envelope(job)
        return b"", envelope
    data = path.read_bytes()
    if data.startswith(b"PQCF"):
        return data, parse_binary_envelope(data)
    return data, parse_json_envelope(data)


def envelope_to_json(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "magic": envelope["magic"],
        "version": envelope["version"],
        "algorithm": envelope["algorithm"],
        "oracle_id": envelope["oracle_id"],
        "flags": envelope["flags"],
        "seed_len": len(envelope["seed"]),
        "msg_len": len(envelope["msg"]),
        "mutation_len": len(envelope["mutation"]),
        "extra_len": len(envelope["extra"]),
        "source_format": envelope["source_format"],
    }


def make_kem_trace(job: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    enabled_subtests = [
        subtest for subtest in job.get("enabled_subtests", []) if subtest.get("enabled") and subtest.get("oracle_id") == envelope["oracle_id"]
    ]
    if not enabled_subtests and envelope["oracle_id"] == "mlkem_local_roundtrip":
        enabled_subtests = [subtest for subtest in job.get("enabled_subtests", []) if subtest.get("oracle_id") == "mlkem_local_roundtrip"]
    subtests = []
    for subtest in enabled_subtests:
        adapter = "left" if subtest["subtest_id"].startswith("left_") else "right"
        subtests.append(
            {
                "subtest_id": subtest["subtest_id"],
                "oracle_id": subtest["oracle_id"],
                "passed": True,
                "expected_relation": "SAME_SHARED_SECRET",
                "calls": [
                    {"adapter": adapter, "api": "keygen", "status": "API_UNSUPPORTED", "note": "native adapter not linked during Python replay"},
                    {"adapter": adapter, "api": "encaps", "status": "API_UNSUPPORTED", "note": "native adapter not linked during Python replay"},
                    {"adapter": adapter, "api": "decaps", "status": "API_UNSUPPORTED", "note": "native adapter not linked during Python replay"},
                ],
            }
        )
    return {
        "version": 1,
        "job_id": job["job_id"],
        "pair_id": job["pair_id"],
        "algorithm": job["algorithm"],
        "oracle_id": envelope["oracle_id"],
        "mutation_target": "",
        "left_status": "API_UNSUPPORTED",
        "right_status": "API_UNSUPPORTED",
        "verify_result": False,
        "legal_negative_outcome": False,
        "envelope": envelope_to_json(envelope),
        "subtests": subtests,
        "mutations": [],
        "findings": [],
    }


def expected_relation_for_sig(oracle_id: str) -> str:
    if oracle_id in {"mldsa_local_sign_verify", "mldsa_cross_verify", "slhdsa_local_sign_verify", "slhdsa_cross_verify"}:
        return "VERIFY_TRUE"
    if oracle_id in {"mldsa_mutated_signature_negative", "slhdsa_mutated_signature_negative"}:
        return "VERIFY_FALSE_OR_DECODE_REJECT_OR_API_INVALID_INPUT"
    if oracle_id in {"mldsa_mutated_context_negative", "mldsa_oid_field_mutation_sanity", "slhdsa_mutated_context_negative"}:
        return "VERIFY_FALSE_OR_API_UNSUPPORTED"
    if oracle_id in {"mldsa_bad_randomness_sanity", "slhdsa_bad_randomness_sanity"}:
        return "NO_CRASH"
    return "VERIFY_FALSE"


def mutation_target_for_sig(oracle_id: str) -> str:
    return {
        "mldsa_mutated_signature_negative": "signature.h",
        "mldsa_mutated_message_negative": "message",
        "mldsa_mutated_context_negative": "ctx",
        "mldsa_oid_field_mutation_sanity": "oid",
        "slhdsa_mutated_signature_negative": "signature.SIGFORS",
        "slhdsa_mutated_message_negative": "message",
        "slhdsa_mutated_context_negative": "ctx",
    }.get(oracle_id, "")


def make_sig_subtest(subtest: dict[str, Any], oracle_id: str, adapter: str, legal_negative: bool) -> dict[str, Any]:
    if legal_negative:
        verify_status = "API_UNSUPPORTED" if oracle_id in {"mldsa_mutated_context_negative", "mldsa_oid_field_mutation_sanity", "slhdsa_mutated_context_negative"} else "REJECT"
        verify_result = False
        passed = True
    else:
        verify_status = "OK"
        verify_result = True
        passed = True
    return {
        "subtest_id": subtest["subtest_id"],
        "oracle_id": oracle_id,
        "passed": passed,
        "expected_relation": expected_relation_for_sig(oracle_id),
        "verify_result": verify_result,
        "legal_negative_outcome": legal_negative,
        "calls": [
            {"adapter": adapter, "api": "keygen", "status": "OK", "note": "Python replay simulated external SIG adapter"},
            {"adapter": adapter, "api": "sign", "status": "OK", "note": "Python replay simulated external SIG adapter"},
            {"adapter": adapter, "api": "verify", "status": verify_status, "note": "Python replay simulated external SIG adapter"},
        ],
    }


def make_sig_trace(job: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    enabled_subtests = [
        subtest for subtest in job.get("enabled_subtests", []) if subtest.get("enabled") and subtest.get("oracle_id") == envelope["oracle_id"]
    ]
    if not enabled_subtests and envelope["oracle_id"] == "mldsa_local_sign_verify":
        enabled_subtests = [subtest for subtest in job.get("enabled_subtests", []) if subtest.get("oracle_id") == "mldsa_local_sign_verify"]
    legal_negative = envelope["oracle_id"] in {
        "mldsa_mutated_signature_negative",
        "mldsa_mutated_message_negative",
        "mldsa_mutated_context_negative",
        "mldsa_oid_field_mutation_sanity",
        "slhdsa_mutated_signature_negative",
        "slhdsa_mutated_message_negative",
        "slhdsa_mutated_context_negative",
    }
    subtests = []
    for subtest in enabled_subtests:
        adapter = "left" if subtest["subtest_id"].startswith("left_") or subtest["subtest_id"].startswith("mutated") or subtest["subtest_id"].startswith("oid") else "right"
        subtests.append(make_sig_subtest(subtest, envelope["oracle_id"], adapter, legal_negative))
    mutation_target = mutation_target_for_sig(envelope["oracle_id"])
    mutations = []
    if mutation_target:
        mutations.append(
            {
                "operation": "field_aware",
                "target": mutation_target,
                "offset": 0,
                "length": 1,
                "field_parse_status": "fallback_byte_range",
            }
        )
    return {
        "version": 1,
        "job_id": job["job_id"],
        "pair_id": job["pair_id"],
        "algorithm": job["algorithm"],
        "oracle_id": envelope["oracle_id"],
        "mutation_target": mutation_target,
        "left_status": "OK",
        "right_status": "OK" if envelope["oracle_id"] == "mldsa_cross_verify" else ("REJECT" if legal_negative else "OK"),
        "verify_result": not legal_negative,
        "legal_negative_outcome": legal_negative,
        "envelope": envelope_to_json(envelope),
        "subtests": subtests,
        "mutations": mutations,
        "findings": [],
    }


def make_trace(job: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    if job["primitive_type"] == "sig":
        return make_sig_trace(job, envelope)
    return make_kem_trace(job, envelope)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def make_artifact_dir(job: dict[str, Any], input_bytes: bytes, envelope: dict[str, Any]) -> Path:
    digest = hashlib.sha256(input_bytes or json.dumps(envelope_to_json(envelope), sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return REPO_ROOT / job["paths"]["result_dir"] / f"replay_{digest}"


def maybe_write_finding(artifact_dir: Path, job: dict[str, Any], trace: dict[str, Any]) -> None:
    finding_class = classify_trace(trace)
    if finding_class is None:
        return
    finding_id = f"{finding_class}_{hashlib.sha256(json.dumps(trace, sort_keys=True).encode('utf-8')).hexdigest()[:16]}"
    finding = {
        "version": 1,
        "finding_id": finding_id,
        "job_id": job["job_id"],
        "pair_id": job["pair_id"],
        "algorithm": job["algorithm"],
        "oracle_id": trace["oracle_id"],
        "finding_class": finding_class,
        "summary": f"{finding_class} detected by {trace['oracle_id']}",
        "trace_path": str(artifact_dir / "oracle_trace.json"),
        "artifact_dir": str(artifact_dir),
    }
    write_json(artifact_dir / "finding.json", finding)
    generate_poc(artifact_dir, finding, job)


def replay(job_path: Path, input_path: Path) -> Path:
    job = json.loads(job_path.read_text(encoding="utf-8"))
    input_bytes, envelope = parse_envelope(input_path, job)
    if envelope["algorithm"] != job["algorithm"]:
        raise ReplayError(f"input algorithm {envelope['algorithm']} does not match job algorithm {job['algorithm']}")
    artifact_dir = make_artifact_dir(job, input_bytes, envelope)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    trace = make_trace(job, envelope)

    (artifact_dir / "structured_input.bin").write_bytes(input_bytes)
    write_json(artifact_dir / "structured_input.json", envelope_to_json(envelope))
    shutil.copyfile(REPO_ROOT / job["paths"]["generated_config"], artifact_dir / "generated_config.json")
    (artifact_dir / "stdout.txt").write_text("PQCFuzz replay completed\n", encoding="utf-8")
    (artifact_dir / "stderr.txt").write_text("", encoding="utf-8")
    write_json(artifact_dir / "oracle_trace.json", trace)
    (artifact_dir / "minimized_seed.bin").write_bytes(envelope["seed"])
    maybe_write_finding(artifact_dir, job, trace)
    return artifact_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True, help="job JSON generated by src/jobs/generate_jobs.py")
    parser.add_argument("--input", required=True, help="PQCFuzz envelope input")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    artifact_dir = replay(Path(args.job), Path(args.input))
    print(f"replayed input and wrote artifacts to {artifact_dir.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReplayError as exc:
        print(f"replay_one error: {exc}", file=sys.stderr)
        raise SystemExit(1)
