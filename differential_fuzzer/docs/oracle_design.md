# Oracle Design

The checked-in implementation now fixes the oracle contract even though the full crypto execution logic is still scaffolded.

## KEM Oracle

Supported scenario classes:

- `left_seeded_keygen_local_roundtrip`
- `right_seeded_keygen_local_roundtrip`
- `left_keypair_cross_impl_encaps_if_allowed`
- `right_keypair_cross_impl_encaps_if_allowed`
- `cross_decaps_if_declared_compatible`
- `corrupt_ciphertext_negative`

Rules:

- never compare shared secrets from unrelated fresh sessions
- only perform cross-exchange scenarios when interop policy allows them
- prefer seeded or derandomized paths when capability flags and determinism policy allow them

## SIG Oracle

Supported scenario classes:

- `left_sign_left_verify`
- `left_sign_right_verify_if_allowed`
- `right_sign_right_verify`
- `right_sign_left_verify_if_allowed`
- `mutated_signature_negative`
- `mutated_message_negative`
- `mutated_public_key_negative`

Rules:

- the primary oracle is verify behavior
- raw signature byte comparison is disabled unless the determinism policy explicitly allows it
- negative-path mutations compare acceptance and rejection semantics, not internal details

## Interop And Determinism Effects

Interop policy determines whether cross-project exchange is legal for a pair.

Determinism policy plus capability flags determine whether seeded or derandomized execution paths should be selected.

## Forbidden Comparisons

- comparing unrelated randomized KEM sessions
- assuming cross-project ciphertext or signature exchange without policy support
- assuming raw signature equality by default
