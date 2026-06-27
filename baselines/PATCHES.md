# Baseline patches

## cryptofuzz

- Changed: `baselines/cryptofuzz/Makefile`
- Reason: redirect top-level object files, generated repository headers, helper binaries, the main fuzzer binary, and the local cpu_features CMake build to `workspace/cryptofuzz/targets-build`.
- Behavior preserved: upstream fuzzing logic unchanged.

## CLFuzz

- Changed: `baselines/CLFuzz/Makefile`
- Reason: redirect top-level object files, generated repository headers, the main fuzzer binary, and the local cpu_features CMake build to `workspace/CLFuzz/targets-build`.
- Behavior preserved: upstream fuzzing logic unchanged.

## cryptoTesting

- Changed: `baselines/cryptoTesting/Makefile`
- Reason: make liboqs checkout/configure/build recipes fail-fast so a failed `git checkout` cannot continue into CMake/Ninja on the wrong revision.
- Behavior preserved: upstream fuzzing logic unchanged.
