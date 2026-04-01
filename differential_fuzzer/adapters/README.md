# Adapters

This directory holds source-of-truth adapter contracts and project-specific adapter code.

Runtime-generated harnesses do not live here. They are emitted under `workspace/tmp/<job_id>/`.

Adapters are responsible for:

- exposing normalized return conventions
- presenting ABI sizes to the harness
- hiding project-specific API differences
- surfacing optional seeded or deterministic entrypoints when available
