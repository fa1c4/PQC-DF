# Baselines

This directory contains vendored baseline fuzzers used by PQC-DF.

These baselines are not Git submodules. Their upstream `.git` directories have been removed, and the source trees are tracked directly by the PQC-DF repository.

Baseline `.gitignore` files are intentionally kept so that upstream build/cache conventions remain visible.

Git platform metadata such as `.github/`, `.gitmodules`, and `.gitattributes` is removed from vendored baselines.

## Baselines

- `cryptofuzz`
- `CLFuzz`
- `cryptoTesting`

## Running baselines

Use the root dispatcher:

```bash
scripts/run_baseline.sh cryptofuzz docker-build
scripts/run_baseline.sh cryptofuzz build
scripts/run_baseline.sh cryptofuzz run

scripts/run_baseline.sh cryptofuzz build --version 0.14.0
scripts/run_baseline.sh cryptofuzz run --version 0.14.0 --mode smoke
scripts/run_baseline.sh cryptofuzz build --version 0.8.0
scripts/run_baseline.sh cryptofuzz run --version 0.8.0 --mode smoke
scripts/run_baseline.sh cryptofuzz build --version 0.4.0
scripts/run_baseline.sh cryptofuzz run --version 0.4.0 --mode smoke

scripts/run_baseline.sh CLFuzz build
scripts/run_baseline.sh CLFuzz run

scripts/run_baseline.sh cryptoTesting build
scripts/run_baseline.sh cryptoTesting run
```

Build artifacts are written to:

```text
workspace/<baseline>/targets-build/
```

Run artifacts are written to:

```text
workspace/<baseline>/targets-run/
```

Baseline source directories should remain clean and should not contain PQC-DF runtime artifacts.

If Docker fails while loading `ubuntu:22.04` metadata, clear the local builder cache and retry. If the registry or mirror still returns inconsistent digests, build with a known-good local or mirror image:

```bash
docker builder prune
scripts/run_baseline.sh cryptofuzz docker-build --base-image ubuntu:22.04
scripts/run_baseline.sh cryptofuzz docker-build --base-image <registry-or-local-image>
```

The same override can be set with `PQCDF_DOCKER_BASE_IMAGE`.
