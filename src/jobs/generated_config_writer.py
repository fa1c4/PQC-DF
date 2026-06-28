#!/usr/bin/env python3
"""Generated job/config materialization helpers for PQCFuzz."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def make_job_id(pair_id: str) -> str:
    return f"job_{pair_id}"


def make_workspace_paths(job_id: str) -> dict[str, str]:
    return {
        "job": f"workspace/jobs/{job_id}.json",
        "generated_config": f"workspace/tmp/{job_id}/generated_config.json",
        "build_dir": f"workspace/build/{job_id}",
        "run_dir": f"workspace/runs/{job_id}",
        "result_dir": f"workspace/results/{job_id}",
        "crash_dir": f"workspace/crashes/{job_id}",
    }


def oracle_ids_for_ml_kem() -> list[str]:
    return [
        "mlkem_local_roundtrip",
        "mlkem_cross_exchange_roundtrip",
        "mlkem_tampered_ciphertext_implicit_rejection",
        "mlkem_bad_randomness_sanity",
    ]


def oracle_ids_for_ml_dsa() -> list[str]:
    return [
        "mldsa_local_sign_verify",
        "mldsa_cross_verify",
        "mldsa_mutated_signature_negative",
        "mldsa_mutated_message_negative",
        "mldsa_mutated_context_negative",
        "mldsa_oid_field_mutation_sanity",
        "mldsa_bad_randomness_sanity",
    ]


def oracle_ids_for_slh_dsa() -> list[str]:
    return [
        "slhdsa_local_sign_verify",
        "slhdsa_cross_verify",
        "slhdsa_mutated_signature_negative",
        "slhdsa_mutated_message_negative",
        "slhdsa_mutated_context_negative",
        "slhdsa_bad_randomness_sanity",
    ]


def oracle_ids_for_pair(pair: dict[str, Any]) -> list[str]:
    if pair["primitive_type"] == "kem":
        return oracle_ids_for_ml_kem()
    if pair["algorithm_family"] == "ML-DSA":
        return oracle_ids_for_ml_dsa()
    if pair["algorithm_family"] == "SLH-DSA":
        return oracle_ids_for_slh_dsa()
    raise ValueError(f"unsupported primitive type: {pair['primitive_type']}")


def oracle_spec_for_pair(pair: dict[str, Any]) -> str:
    if pair["primitive_type"] == "kem":
        return "src/oracles/specs/ml_kem.json"
    if pair["algorithm_family"] == "ML-DSA":
        return "src/oracles/specs/ml_dsa.json"
    if pair["algorithm_family"] == "SLH-DSA":
        return "src/oracles/specs/slh_dsa.json"
    raise ValueError(f"unsupported primitive type: {pair['primitive_type']}")


def fuzzer_source_for_pair(pair: dict[str, Any]) -> str:
    if pair["primitive_type"] == "kem":
        return "src/fuzzers/kem_pair_fuzzer.cc"
    if pair["primitive_type"] == "sig":
        return "src/fuzzers/sig_pair_fuzzer.cc"
    raise ValueError(f"unsupported primitive type: {pair['primitive_type']}")


def kem_enabled_subtests(exchange_contract: dict[str, bool]) -> list[dict[str, Any]]:
    subtests: list[dict[str, Any]] = [
        {
            "subtest_id": "left_keygen_left_encaps_left_decaps",
            "oracle_id": "mlkem_local_roundtrip",
            "required_exchange": [],
            "enabled": True,
        },
        {
            "subtest_id": "right_keygen_right_encaps_right_decaps",
            "oracle_id": "mlkem_local_roundtrip",
            "required_exchange": [],
            "enabled": True,
        },
        {
            "subtest_id": "left_keygen_right_encaps_left_decaps",
            "oracle_id": "mlkem_cross_exchange_roundtrip",
            "required_exchange": ["public_key_exchange", "ciphertext_exchange"],
            "enabled": exchange_contract["public_key_exchange"] and exchange_contract["ciphertext_exchange"],
        },
        {
            "subtest_id": "right_keygen_left_encaps_right_decaps",
            "oracle_id": "mlkem_cross_exchange_roundtrip",
            "required_exchange": ["public_key_exchange", "ciphertext_exchange"],
            "enabled": exchange_contract["public_key_exchange"] and exchange_contract["ciphertext_exchange"],
        },
        {
            "subtest_id": "left_keygen_left_encaps_right_decaps",
            "oracle_id": "mlkem_cross_exchange_roundtrip",
            "required_exchange": ["ciphertext_exchange", "secret_key_exchange"],
            "enabled": exchange_contract["ciphertext_exchange"] and exchange_contract["secret_key_exchange"],
        },
        {
            "subtest_id": "right_keygen_right_encaps_left_decaps",
            "oracle_id": "mlkem_cross_exchange_roundtrip",
            "required_exchange": ["ciphertext_exchange", "secret_key_exchange"],
            "enabled": exchange_contract["ciphertext_exchange"] and exchange_contract["secret_key_exchange"],
        },
        {
            "subtest_id": "tampered_ciphertext_negative",
            "oracle_id": "mlkem_tampered_ciphertext_implicit_rejection",
            "required_exchange": [],
            "enabled": True,
        },
    ]
    return subtests


def sig_enabled_subtests(exchange_contract: dict[str, bool], oracle_prefix: str) -> list[dict[str, Any]]:
    cross_verify_enabled = exchange_contract["public_key_exchange"] and exchange_contract["signature_exchange"]
    local_oracle = f"{oracle_prefix}_local_sign_verify"
    cross_oracle = f"{oracle_prefix}_cross_verify"
    mutated_signature_oracle = f"{oracle_prefix}_mutated_signature_negative"
    mutated_message_oracle = f"{oracle_prefix}_mutated_message_negative"
    mutated_context_oracle = f"{oracle_prefix}_mutated_context_negative"
    bad_randomness_oracle = f"{oracle_prefix}_bad_randomness_sanity"
    return [
        {
            "subtest_id": "left_keygen_left_sign_left_verify",
            "oracle_id": local_oracle,
            "required_exchange": [],
            "enabled": True,
        },
        {
            "subtest_id": "right_keygen_right_sign_right_verify",
            "oracle_id": local_oracle,
            "required_exchange": [],
            "enabled": True,
        },
        {
            "subtest_id": "left_keygen_left_sign_right_verify",
            "oracle_id": cross_oracle,
            "required_exchange": ["public_key_exchange", "signature_exchange"],
            "enabled": cross_verify_enabled,
        },
        {
            "subtest_id": "right_keygen_right_sign_left_verify",
            "oracle_id": cross_oracle,
            "required_exchange": ["public_key_exchange", "signature_exchange"],
            "enabled": cross_verify_enabled,
        },
        {
            "subtest_id": "mutated_signature_negative",
            "oracle_id": mutated_signature_oracle,
            "required_exchange": [],
            "enabled": True,
        },
        {
            "subtest_id": "mutated_message_negative",
            "oracle_id": mutated_message_oracle,
            "required_exchange": [],
            "enabled": True,
        },
        {
            "subtest_id": "mutated_context_negative",
            "oracle_id": mutated_context_oracle,
            "required_exchange": [],
            "enabled": True,
        },
        {
            "subtest_id": "bad_randomness_sanity",
            "oracle_id": bad_randomness_oracle,
            "required_exchange": [],
            "enabled": True,
        },
    ]


def enabled_subtests_for_pair(pair: dict[str, Any]) -> list[dict[str, Any]]:
    if pair["primitive_type"] == "kem":
        return kem_enabled_subtests(pair["exchange_contract"])
    if pair["algorithm_family"] == "ML-DSA":
        subtests = sig_enabled_subtests(pair["exchange_contract"], "mldsa")
        subtests.insert(
            -1,
            {
                "subtest_id": "oid_field_mutation_sanity",
                "oracle_id": "mldsa_oid_field_mutation_sanity",
                "required_exchange": [],
                "enabled": True,
            },
        )
        return subtests
    if pair["algorithm_family"] == "SLH-DSA":
        return sig_enabled_subtests(pair["exchange_contract"], "slhdsa")
    raise ValueError(f"unsupported primitive type: {pair['primitive_type']}")


def make_job_record(pair: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    job_id = make_job_id(pair["pair_id"])
    paths = make_workspace_paths(job_id)
    return {
        "version": 1,
        "job_id": job_id,
        "pair_id": pair["pair_id"],
        "algorithm": pair["algorithm"],
        "algorithm_family": pair["algorithm_family"],
        "primitive_type": pair["primitive_type"],
        "algorithm_metadata": pair["algorithm_metadata"],
        "pair": {
            "left": pair["left"],
            "right": pair["right"],
            "exchange_contract": pair["exchange_contract"],
            "provenance_relation": pair["provenance_relation"],
        },
        "oracle_spec": oracle_spec_for_pair(pair),
        "oracles": oracle_ids_for_pair(pair),
        "enabled_subtests": enabled_subtests_for_pair(pair),
        "fuzzer_source": fuzzer_source_for_pair(pair),
        "paths": paths,
        "status": "pending",
    }


def make_generated_config(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": 1,
        "job_id": job["job_id"],
        "pair_id": job["pair_id"],
        "algorithm": job["algorithm"],
        "algorithm_family": job["algorithm_family"],
        "primitive_type": job["primitive_type"],
        "algorithm_metadata": job["algorithm_metadata"],
        "pair": job["pair"],
        "oracles": job["oracles"],
        "enabled_subtests": job["enabled_subtests"],
        "paths": {
            "result_dir": job["paths"]["result_dir"],
            "crash_dir": job["paths"]["crash_dir"],
            "run_dir": job["paths"]["run_dir"],
            "generated_config": job["paths"]["generated_config"],
        },
    }


def materialize_job(repo_root: Path, job: dict[str, Any]) -> None:
    generated_config = make_generated_config(job)
    for key in ("build_dir", "run_dir", "result_dir", "crash_dir"):
        (repo_root / job["paths"][key]).mkdir(parents=True, exist_ok=True)
    write_json(repo_root / job["paths"]["generated_config"], generated_config)
    write_json(repo_root / job["paths"]["job"], job)
