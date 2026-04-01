# PQ-CDF

PQ-CDF is a framework for post-quantum crypto differential fuzzing built around three explicit layers:

1. Operation-level mapping
2. Flow-level pairing
3. Self-sufficient job generation

The repository is structured to keep source-of-truth contracts separate from runtime artifacts, use stock libFuzzer, and generate one fuzzer binary per flow pair.

## Status

This repository now includes the architecture scaffold plus the first working pipeline for:

- manual operation mapping normalization
- flow-level bundle pairing
- self-sufficient fuzzer job generation
- runtime-generated harness and config emission under `workspace/tmp/<job_id>/`

Adapter implementations, semantic oracle execution, native compilation, fuzz runs, and replay/finding recording are scaffolded but not implemented yet.

## Layout

```text
/design_implementation_mapper
/pairing_differential_targets
/differential_fuzzer
/eval
/projects
/workspace
```

## Quickstart

Generate normalized mappings:

```bash
python3 design_implementation_mapper/mapper.py
```

Generate flow pairs:

```bash
python3 pairing_differential_targets/pairing.py
```

Generate job records and runtime harness/config artifacts:

```bash
python3 differential_fuzzer/diff_fuzzer.py
```

## Current scope

- Projects: `liboqs`, `PQClean`
- Families: `ML-KEM`, `ML-DSA`
- Primitive types: `kem`, `sig`
- Pairing policy: exact complete bundles only
- Runtime artifacts: isolated by `job_id`

## Notes

- `projects/` is reserved for upstream source trees only.
- `workspace/` is reserved for runtime outputs only.
- Checked-in templates live under `differential_fuzzer/templates/`.
- Generated harnesses never live in source-of-truth directories.

