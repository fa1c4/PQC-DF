# Mapping Contract

`design_implementation_mapper` is the canonical operation-level mapper for PQ-CDF.

## Purpose

The mapper bridges standardized semantic operations to concrete implementation entries. It is manual-first and metadata-rich by design.

For each mapped operation, the mapper records:

- semantic identity
- project identity
- implementation identity
- downstream symbol reference
- downstream build metadata
- downstream ABI metadata
- downstream capability metadata

## Inputs

- `config/mapper.config.json`
- `data/mapping.manual.json`
- project roots under `projects/`

## Output

- `data/mapping.json`

## Manual Workflow

1. Author operation-level mappings in `data/mapping.manual.json`.
2. Run `python3 design_implementation_mapper/mapper.py`.
3. Let the mapper validate, normalize, deduplicate, and canonicalize the records.
4. Consume the resulting `data/mapping.json` downstream.

## Semantic Key Format

Semantic keys use:

`{ALGORITHM}/{operation}`

Examples:

- `ML-KEM-768/keygen`
- `ML-KEM-768/encaps`
- `ML-KEM-768/decaps`
- `ML-DSA-65/keygen`
- `ML-DSA-65/sign`
- `ML-DSA-65/verify`

## Output Format

The output stays strictly operation-level. Each top-level key is a semantic operation, and each value is grouped by machine-readable `project_id`.

```json
{
  "ML-KEM-768/keygen": {
    "liboqs": [
      {
        "project_id": "liboqs",
        "project_name": "liboqs",
        "implementation_id": "liboqs_mlkem768_wrapper_generic",
        "source_file": "src/kem/ml_kem/kem_ml_kem_768.c",
        "function": "OQS_KEM_ml_kem_768_keypair",
        "primitive_type": "kem",
        "api_variant": "wrapper",
        "backend_variant": "generic",
        "status": "enabled",
        "build": {},
        "abi": {},
        "capabilities": {},
        "provenance_hint": "manual"
      }
    ]
  }
}
```

## Identity Model

Each descriptor must carry:

- `project_id`
- `project_name`
- `implementation_id`
- `api_variant`
- `backend_variant`

`implementation_id` is the stable downstream identity used for bundle construction, pair identity, and collision prevention.

## Build Metadata

Each descriptor must include a `build` object with:

- `build_mode`
- `implementation_dir`
- `declaration_file`
- `implementation_files`
- `include_dirs`
- `common_deps`
- `defines`

The mapper does not build targets, but it must provide enough metadata so downstream build orchestration never has to guess.

## ABI Metadata

Each descriptor must include:

- KEM: `pk_len`, `sk_len`, `ct_len`, `ss_len`
- SIG: `pk_len`, `sk_len`, `sig_max_len`

Unused ABI fields are normalized to `null`.

## Capability Metadata

Each descriptor must include:

- `supports_keygen_derand`
- `supports_encaps_derand`
- `supports_sign_derand`
- `wire_format_class`
- `interop_class`

These fields expose facts and declarations used later by pairing and fuzzing.

## Validation Rules

The mapper validates:

- structure and JSON shape
- semantic key format
- allowed projects and algorithms
- allowed primitive and status values
- machine-readable naming for `project_id` and `implementation_id`
- build metadata shape
- ABI shape by primitive type
- capability metadata shape
- consistent reuse of `implementation_id`
- optional filesystem and function-name checks when enabled

## Normalization Rules

The mapper guarantees:

- deterministic semantic-key ordering
- deterministic project ordering
- deterministic descriptor ordering
- canonical machine-readable identities
- duplicate elimination by semantic key, project, implementation, function, and source file
- consistent optional field normalization

## Non-Goals

The mapper does not:

- construct flow bundles
- pair implementations
- generate fuzzer jobs
- generate harnesses
- build targets
- run fuzzers
- do heuristic discovery
- do provenance inference
- perform bridge matching
