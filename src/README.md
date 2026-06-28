# PQCFuzz Active Source Tree

`src/` is the active PQCFuzz implementation for FIPS 203 ML-KEM, FIPS 204
ML-DSA, and FIPS 205 SLH-DSA external-API differential fuzzing.

This path is intentionally driven by an explicit pair file:

```bash
python3 src/pairing/validate_pair_alg.py \
  --pair-alg src/config/pair_alg.default.json

python3 src/jobs/generate_jobs.py \
  --pair-alg src/config/pair_alg.default.json \
  --algorithm-family ML-KEM

python3 src/jobs/generate_jobs.py \
  --pair-alg src/config/pair_alg.default.json \
  --algorithm-family ML-DSA

python3 src/jobs/generate_jobs.py \
  --pair-alg src/config/pair_alg.default.json \
  --algorithm-family SLH-DSA
```

The generator only consumes pair records supplied by `--pair-alg`; it does not
infer implementation provenance or compatibility. Generated jobs and runtime
configs are written under `workspace/jobs/` and `workspace/tmp/`.

Replay accepts PQCFuzz envelope inputs and writes structured traces/artifacts:

```bash
python3 src/replay/replay_one.py \
  --job workspace/jobs/<mlkem_job>.json \
  --input tests/seeds/mlkem_roundtrip_seed.bin

python3 src/replay/replay_one.py \
  --job workspace/jobs/<mldsa_job>.json \
  --input tests/seeds/mldsa_sign_verify_seed.bin

python3 src/replay/replay_one.py \
  --job workspace/jobs/<slhdsa_job>.json \
  --input tests/seeds/slhdsa_sign_verify_seed.bin
```

Baselines remain outside this active implementation and are not modified by the
PQCFuzz FIPS 203 path.
