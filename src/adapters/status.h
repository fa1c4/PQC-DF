#ifndef PQCFUZZ_ADAPTERS_STATUS_H
#define PQCFUZZ_ADAPTERS_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pqcfuzz_status {
  PQCFUZZ_OK = 0,
  PQCFUZZ_REJECT = 1,
  PQCFUZZ_INVALID_INPUT = 2,
  PQCFUZZ_CRASH = 3,
  PQCFUZZ_TIMEOUT = 4,
  PQCFUZZ_API_UNSUPPORTED = 5
} pqcfuzz_status;

const char *pqcfuzz_status_to_string(pqcfuzz_status status);
pqcfuzz_status pqcfuzz_status_from_string(const char *status);
pqcfuzz_status pqcfuzz_normalize_return_code(int rc);

#ifdef __cplusplus
}
#endif

#endif
