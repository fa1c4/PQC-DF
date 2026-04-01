# Harness Design

Generated harnesses are runtime artifacts under `workspace/tmp/<job_id>/`. Checked-in templates remain the source of truth.

## Template Responsibilities

Each template provides:

- stock libFuzzer entrypoint: `LLVMFuzzerTestOneInput`
- structured-input decoding scaffold
- job and pair identity constants
- ABI and determinism placeholders
- interop-policy placeholders
- enabled-subtest placeholders
- mismatch-label placeholders
- generated-config path binding

## Structured Input Format

Harnesses use a light structured envelope instead of passing raw fuzzer bytes directly into crypto APIs:

```text
[mode_byte]
[flag_byte]
[msg_len]
[msg_bytes]
[seed_len]
[seed_bytes]
[mutation_len]
[mutation_bytes]
[extra_bytes...]
```

Malformed harness-level input returns `-1`. Crypto-level failures remain part of oracle behavior and do not mark the input malformed.

## Runtime Artifact Policy

- Templates are checked in under `differential_fuzzer/templates/`.
- Generated harnesses never live in source-of-truth directories.
- The generated harness reads job-specific configuration through `generated_config.json`.

## Failure Behavior

Crash-time mutation of shared JSON state is intentionally avoided. Replay is the preferred path for final structured finding emission.
