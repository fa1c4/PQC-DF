#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/run_baseline.sh cryptoTesting run [options]

Options:
  --version VERSION             Reproduce cryptoTesting on a supported liboqs version.
  --mode functional             Run the main functional workflow. Default.
  --skip-core-pattern-check     Skip the host AFL core_pattern preflight.
  -h, --help                    Show this help.

Supported versions:
  0.14.0                        Uses upstream target ches_liboqs.
  0.8.0                         Uses upstream target cur_liboqs.
  0.4.0                         Uses upstream target mid_liboqs.

Examples:
  scripts/run_baseline.sh cryptoTesting run --version 0.14.0
  scripts/run_baseline.sh cryptoTesting run --version 0.8.0
  scripts/run_baseline.sh cryptoTesting run --version 0.4.0
  scripts/run_baseline.sh cryptoTesting run --version 0.14.0 --skip-core-pattern-check
EOF
}

BASELINE_DIR="$1"
BUILD_DIR="$2"
RUN_DIR="$3"
shift 3

VERSION="0.14.0"
MODE="functional"
SKIP_CORE_PATTERN_CHECK=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --version." >&2
        exit 2
      fi
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#--version=}"
      shift
      ;;
    --mode)
      if [ "$#" -lt 2 ]; then
        echo "Missing value for --mode." >&2
        exit 2
      fi
      MODE="$2"
      shift 2
      ;;
    --mode=*)
      MODE="${1#--mode=}"
      shift
      ;;
    --skip-core-pattern-check)
      SKIP_CORE_PATTERN_CHECK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ "$MODE" != "functional" ]; then
  echo "Unsupported cryptoTesting mode: $MODE" >&2
  echo "Supported mode: functional" >&2
  exit 2
fi

IMAGE_NAME="pqcdf-baseline-cryptotesting"

case "$VERSION" in
  0.14.0)
    LIBOQS_TARGET="ches_liboqs"
    ;;
  0.8.0)
    LIBOQS_TARGET="cur_liboqs"
    ;;
  0.4.0)
    LIBOQS_TARGET="mid_liboqs"
    ;;
  *)
    echo "Unsupported cryptoTesting liboqs version: $VERSION" >&2
    echo "Supported versions: 0.14.0, 0.8.0, 0.4.0" >&2
    exit 2
    ;;
esac

mkdir -p "$BUILD_DIR" "$RUN_DIR"

BUILD_DIR_ABS="$(realpath "$BUILD_DIR")"
RUN_DIR_ABS="$(realpath "$RUN_DIR")"
BUILD_TARGET_DIR="${BUILD_DIR_ABS}/${LIBOQS_TARGET}"
REPORTS_DIR="${RUN_DIR_ABS}/reports"
LOG_DIR="${RUN_DIR_ABS}/logs"
LOG_FILE="${LOG_DIR}/${LIBOQS_TARGET}.${MODE}.log"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

echo "[cryptoTesting] build directory: $BUILD_DIR"
echo "[cryptoTesting] run directory: $RUN_DIR"
echo "[cryptoTesting] liboqs version: $VERSION"
echo "[cryptoTesting] liboqs target: $LIBOQS_TARGET"
echo "[cryptoTesting] mode: $MODE"

if [ "$SKIP_CORE_PATTERN_CHECK" -eq 0 ]; then
  CORE_PATTERN="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)"
  if [ "$CORE_PATTERN" != "core" ]; then
    echo "Host /proc/sys/kernel/core_pattern is '$CORE_PATTERN', expected 'core'." >&2
    echo "Run: sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'" >&2
    echo "Or pass --skip-core-pattern-check if this is managed externally." >&2
    exit 1
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run cryptoTesting through this wrapper." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed, but the Docker daemon is not available to this user." >&2
  exit 1
fi

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "Docker image not found: $IMAGE_NAME" >&2
  echo "Run: scripts/run_baseline.sh cryptoTesting docker-build" >&2
  exit 1
fi

case "$BUILD_TARGET_DIR" in
  "$BUILD_DIR_ABS"/*) ;;
  *)
    echo "Refusing to recreate unexpected build target: $BUILD_TARGET_DIR" >&2
    exit 1
    ;;
esac

if rm -rf "$BUILD_TARGET_DIR" 2>/dev/null; then
  mkdir -p "$BUILD_TARGET_DIR"
else
  echo "[cryptoTesting] host cleanup could not remove $BUILD_TARGET_DIR"
  echo "[cryptoTesting] retrying cleanup inside Docker"
  docker run --rm \
    -v "${BUILD_DIR_ABS}:/pqcdf-build" \
    "$IMAGE_NAME" \
    bash -lc "rm -rf /pqcdf-build/${LIBOQS_TARGET} && mkdir -p /pqcdf-build/${LIBOQS_TARGET}"
fi

mkdir -p "$REPORTS_DIR" "$LOG_DIR"

echo "[cryptoTesting] reports directory: $REPORTS_DIR"
echo "[cryptoTesting] log file: $LOG_FILE"

set +e
docker run --rm \
  -v "${BUILD_TARGET_DIR}:/fuzzing/${LIBOQS_TARGET}" \
  -v "${REPORTS_DIR}:/fuzzing/reports" \
  -v "${LOG_DIR}:/pqcdf-logs" \
  -w /fuzzing \
  "$IMAGE_NAME" \
  bash -lc "trap 'chown -R ${HOST_UID}:${HOST_GID} /fuzzing/${LIBOQS_TARGET} /fuzzing/reports /pqcdf-logs 2>/dev/null || true' EXIT; git config --global --add safe.directory /fuzzing/${LIBOQS_TARGET}; cd /fuzzing && bash -e reproduce.sh ${LIBOQS_TARGET}" \
  2>&1 | tee "$LOG_FILE"
DOCKER_STATUS="${PIPESTATUS[0]}"
set -e

if [ "$DOCKER_STATUS" -ne 0 ]; then
  echo "[cryptoTesting] reproduction failed with status $DOCKER_STATUS" >&2
  echo "[cryptoTesting] see log: $LOG_FILE" >&2
  exit "$DOCKER_STATUS"
fi

echo "[cryptoTesting] reproduction completed"
echo "[cryptoTesting] reports: $REPORTS_DIR"
echo "[cryptoTesting] log: $LOG_FILE"
