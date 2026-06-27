# Baseline patches

## cryptofuzz

- Changed: `baselines/cryptofuzz/Makefile`
- Reason: redirect top-level object files, generated repository headers, helper binaries, the main fuzzer binary, and the local cpu_features CMake build to `workspace/cryptofuzz/targets-build`.
- Behavior preserved: upstream fuzzing logic unchanged.
- Changed: `baselines/cryptofuzz/{gen_repository.py,entry.cpp,driver.cpp,executor.cpp,executor.h,operation.cpp,include/cryptofuzz/module.h,include/cryptofuzz/operations.h}` and added `baselines/cryptofuzz/modules/liboqs/`.
- Reason: add first-class liboqs KEM/SIG self-check operations and a version-specific liboqs module for reproducing PQ baseline campaigns.
- Behavior preserved: existing non-liboqs cryptofuzz operations remain opt-in through the original operation/module controls.
- Changed: `baselines/cryptofuzz/Dockerfile` and `scripts/run_baseline.sh`
- Reason: keep `ubuntu:22.04` as the default Docker base image while allowing `--base-image` or `PQCDF_DOCKER_BASE_IMAGE` overrides when Docker Hub or a registry mirror returns inconsistent base-image metadata.
- Behavior preserved: default Docker build command still builds the same baseline image.

## CLFuzz

- Changed: `baselines/CLFuzz/Makefile`
- Reason: redirect top-level object files, generated repository headers, the main fuzzer binary, and the local cpu_features CMake build to `workspace/CLFuzz/targets-build`.
- Behavior preserved: upstream fuzzing logic unchanged.

## cryptoTesting

- Changed: `baselines/cryptoTesting/Makefile`
- Reason: make liboqs checkout/configure/build recipes fail-fast so a failed `git checkout` cannot continue into CMake/Ninja on the wrong revision.
- Behavior preserved: upstream fuzzing logic unchanged.
