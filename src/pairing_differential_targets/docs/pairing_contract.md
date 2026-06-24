# Pairing Contract

`pairing_differential_targets` converts canonical operation-level mappings into canonical flow-level differential pairs.

## Input

- `../design_implementation_mapper/data/mapping.json`
- `config/pairing.config.json`

The input remains operation-level. Each top-level key is a semantic operation of the form `{ALGORITHM}/{operation}`.

## Output

- `data/pairs.json`

The output is a root JSON array of flow-level pair records. Each record contains one complete left bundle, one complete right bundle, explicit interop policy, provenance summary, and status.

## Bundle Construction

Pairing happens in two stages:

1. Normalize operation-level records into flat candidate records.
2. Group candidates into bundles keyed by:
   `family`, `parameter_set`, `primitive_type`, `project_id`, `implementation_id`

Required operation sets:

- KEM: `keygen`, `encaps`, `decaps`
- SIG: `keygen`, `sign`, `verify`

Incomplete bundles are rejected before pairing.

## Bundle Validation

All operations inside a bundle must agree on:

- `family`
- `parameter_set`
- `primitive_type`
- `project_id`
- `project_name`
- `implementation_id`
- `api_variant`
- `backend_variant`
- build metadata relevant to downstream compilation
- ABI metadata relevant to the primitive type
- framework-relevant capability metadata

Only statuses allowed by config participate in bundle construction.

## Pair Generation

A valid pair must satisfy all of the following:

- left and right are complete valid bundles
- left and right are from different projects
- left and right match on `family`, `parameter_set`, and `primitive_type`
- the project combination is allowed by config
- the selected implementations are allowed by config
- backend variants are allowed by config
- interop policy is derivable and acceptable for the primitive type
- the emitted left/right order is stable

## Interop Policy

Pairing does not assume cross-project wire compatibility. Each pair carries explicit declared policy.

- KEM pairs include: `public_key_exchange`, `ciphertext_exchange`
- SIG pairs include: `public_key_exchange`, `signature_exchange`

Allowed policy values:

- `declared-compatible`
- `same-project-only`
- `no-cross-exchange`
- `manual-review`

The interop policy constrains downstream oracle choices even when a pair itself is still valid.

## Naming

Canonical `pair_id` format:

`{family_slug}{parameter}_{left_project_id}_{left_implementation_id}_vs_{right_project_id}_{right_implementation_id}`

This ID is collision-safe and stable across repeated runs.

## Filtering

The config controls:

- enabled projects
- allowed project combinations
- allowed primitive types
- allowed statuses
- allowed implementations
- allowed backend variants
- backend variant priority
- required operations
- allowed interop policy values by primitive type

## Error Handling

The module fails without writing partial output when:

- config is missing or malformed
- `mapping.json` is missing or malformed
- semantic keys cannot be parsed
- required pairing fields are missing
- bundles are incomplete
- bundles are inconsistent
- generated pairs are invalid

## Non-Goals

This module does not:

- rediscover symbols
- scan source trees
- build binaries
- generate jobs or harnesses
- run fuzzers
- perform heuristic matching
- implement bridge matching
