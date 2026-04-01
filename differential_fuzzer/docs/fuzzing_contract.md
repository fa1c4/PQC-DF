# Fuzzing Contract

`differential_fuzzer` converts validated flow-level pairs into self-sufficient fuzzing jobs and job-scoped runtime artifacts.

## Inputs

- `../pairing_differential_targets/data/pairs.json`
- `config/fuzzing.config.json`
- `templates/kem_pair_fuzzer.cpp`
- `templates/sig_pair_fuzzer.cpp`

## Source-Of-Truth Output

- `data/fuzzer_jobs.json`

## Runtime-Generated Outputs

- `workspace/tmp/<job_id>/generated_harness.cpp`
- `workspace/tmp/<job_id>/generated_config.json`

## Required Job Fields

Each job record must include:

- pair identity
- primitive identity
- selected harness template
- generated artifact paths
- workspace build/run/result/crash paths
- oracle mode
- enabled subtests
- determinism policy
- explicit interop policy
- mismatch labels
- sanitizer and resource defaults
- replay and crash-artifact policy
- full left and right bundle metadata

`fuzzer_jobs.json` is the `/eval` handoff manifest. `/eval` should not need to reopen `pairs.json` or `mapping.json`.

## Workspace Path Rules

Generated runtime artifacts live only under `workspace/tmp/<job_id>/`.

Later build and run outputs are isolated by the same `job_id` under:

- `workspace/build/<job_id>/`
- `workspace/runs/<job_id>/`
- `workspace/results/<job_id>/`
- `workspace/crashes/<job_id>/`

## Build Handoff Contract

The fuzzer job must already carry enough left/right metadata for build orchestration:

- operation symbols
- build metadata
- ABI metadata
- capability metadata
- interop policy
- determinism policy

## Non-Goals

This module does not:

- build binaries
- run fuzzers
- replay inputs
- rediscover mappings
- pair implementations
- modify libFuzzer
