# Adapter Contract

Adapters expose metadata plus normalized function tables so harness templates do not need to know project-specific APIs.

## Required Metadata

- project identity
- implementation identity
- ABI sizes
- optional init and cleanup hooks

## KEM Interface

Required functions:

- `keygen`
- `encaps`
- `decaps`

Optional functions:

- `keygen_derand`
- `encaps_derand`
- `init`
- `cleanup`

## SIG Interface

Required functions:

- `keygen`
- `sign`
- `verify`

Optional functions:

- `sign_derand`
- `init`
- `cleanup`

## Return Normalization

All adapter functions normalize upstream conventions into framework semantics:

- `0` means success
- non-zero means failure

Null optional function pointers indicate that the seeded or deterministic path is unavailable.
