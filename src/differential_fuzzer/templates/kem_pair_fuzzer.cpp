#include <cstddef>
#include <cstdint>

#include "differential_fuzzer/adapters/adapter_interface.h"

#ifndef PQCDF_GENERATED_CONFIG_PATH
#define PQCDF_GENERATED_CONFIG_PATH "{{GENERATED_CONFIG_PATH}}"
#endif

static const char *kJobId = "{{JOB_ID}}";
static const char *kPairId = "{{PAIR_ID}}";
static const char *kOracleMode = "{{ORACLE_MODE}}";
static const char *kLeftImplementationId = "{{LEFT_IMPLEMENTATION_ID}}";
static const char *kRightImplementationId = "{{RIGHT_IMPLEMENTATION_ID}}";
static const char *kResultDir = "{{RESULT_DIR}}";
static const char *kCrashDir = "{{CRASH_DIR}}";
static const char *kEnabledSubtests[] = { {{ENABLED_SUBTESTS}} };
static const char *kMismatchLabels[] = { {{MISMATCH_LABELS}} };

static constexpr size_t kLeftPkLen = {{LEFT_PK_LEN}};
static constexpr size_t kLeftSkLen = {{LEFT_SK_LEN}};
static constexpr size_t kLeftCtLen = {{LEFT_CT_LEN}};
static constexpr size_t kLeftSsLen = {{LEFT_SS_LEN}};
static constexpr size_t kRightPkLen = {{RIGHT_PK_LEN}};
static constexpr size_t kRightSkLen = {{RIGHT_SK_LEN}};
static constexpr size_t kRightCtLen = {{RIGHT_CT_LEN}};
static constexpr size_t kRightSsLen = {{RIGHT_SS_LEN}};

static constexpr bool kPreferSeededKeygen = {{PREFER_SEEDED_KEYGEN}};
static constexpr bool kPreferSeededEncaps = {{PREFER_SEEDED_ENCAPS}};
static constexpr bool kCrossExchangeAllowed = {{CROSS_EXCHANGE_ALLOWED}};

struct ParsedKemInput {
  uint8_t mode;
  uint8_t flags;
  const uint8_t *message;
  size_t message_len;
  const uint8_t *seed;
  size_t seed_len;
  const uint8_t *mutation;
  size_t mutation_len;
  const uint8_t *extra;
  size_t extra_len;
};

static bool ReadByte(const uint8_t *data, size_t size, size_t *offset, uint8_t *value) {
  if (*offset >= size) {
    return false;
  }
  *value = data[*offset];
  *offset += 1;
  return true;
}

static bool ReadSlice(
    const uint8_t *data,
    size_t size,
    size_t *offset,
    uint8_t length,
    const uint8_t **start,
    size_t *slice_len) {
  if (*offset + length > size) {
    return false;
  }
  *start = data + *offset;
  *slice_len = static_cast<size_t>(length);
  *offset += length;
  return true;
}

static bool ParseKemInput(const uint8_t *data, size_t size, ParsedKemInput *parsed) {
  size_t offset = 0;
  uint8_t msg_len = 0;
  uint8_t seed_len = 0;
  uint8_t mutation_len = 0;

  if (!ReadByte(data, size, &offset, &parsed->mode) ||
      !ReadByte(data, size, &offset, &parsed->flags) ||
      !ReadByte(data, size, &offset, &msg_len) ||
      !ReadSlice(data, size, &offset, msg_len, &parsed->message, &parsed->message_len) ||
      !ReadByte(data, size, &offset, &seed_len) ||
      !ReadSlice(data, size, &offset, seed_len, &parsed->seed, &parsed->seed_len) ||
      !ReadByte(data, size, &offset, &mutation_len) ||
      !ReadSlice(data, size, &offset, mutation_len, &parsed->mutation, &parsed->mutation_len)) {
    return false;
  }

  parsed->extra = data + offset;
  parsed->extra_len = size - offset;
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ParsedKemInput input = {};
  if (!ParseKemInput(data, size, &input)) {
    return -1;
  }

  (void)kJobId;
  (void)kPairId;
  (void)kOracleMode;
  (void)kLeftImplementationId;
  (void)kRightImplementationId;
  (void)kResultDir;
  (void)kCrashDir;
  (void)kEnabledSubtests;
  (void)kMismatchLabels;
  (void)kLeftPkLen;
  (void)kLeftSkLen;
  (void)kLeftCtLen;
  (void)kLeftSsLen;
  (void)kRightPkLen;
  (void)kRightSkLen;
  (void)kRightCtLen;
  (void)kRightSsLen;
  (void)kPreferSeededKeygen;
  (void)kPreferSeededEncaps;
  (void)kCrossExchangeAllowed;
  (void)input;

  // TODO: bind the left and right KEM adapters.
  // TODO: dispatch structured scenarios based on input.mode.
  // TODO: prefer seeded keygen and encaps when both policy and capability allow it.
  // TODO: enforce interop policy before attempting cross-implementation exchange.
  // TODO: record only minimal crash-time artifacts and finalize findings in replay.
  (void)PQCDF_GENERATED_CONFIG_PATH;
  return 0;
}
