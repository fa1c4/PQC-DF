#include "adapters/status.h"

#include <cstring>

const char *pqcfuzz_status_to_string(pqcfuzz_status status) {
  switch (status) {
    case PQCFUZZ_OK:
      return "OK";
    case PQCFUZZ_REJECT:
      return "REJECT";
    case PQCFUZZ_INVALID_INPUT:
      return "INVALID_INPUT";
    case PQCFUZZ_CRASH:
      return "CRASH";
    case PQCFUZZ_TIMEOUT:
      return "TIMEOUT";
    case PQCFUZZ_API_UNSUPPORTED:
      return "API_UNSUPPORTED";
  }
  return "INVALID_INPUT";
}

pqcfuzz_status pqcfuzz_status_from_string(const char *status) {
  if (status == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (std::strcmp(status, "OK") == 0) {
    return PQCFUZZ_OK;
  }
  if (std::strcmp(status, "REJECT") == 0) {
    return PQCFUZZ_REJECT;
  }
  if (std::strcmp(status, "INVALID_INPUT") == 0) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (std::strcmp(status, "CRASH") == 0) {
    return PQCFUZZ_CRASH;
  }
  if (std::strcmp(status, "TIMEOUT") == 0) {
    return PQCFUZZ_TIMEOUT;
  }
  if (std::strcmp(status, "API_UNSUPPORTED") == 0) {
    return PQCFUZZ_API_UNSUPPORTED;
  }
  return PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status pqcfuzz_normalize_return_code(int rc) {
  return rc == 0 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
}
