#include "adapters/adapter_interface.h"

#include <cstring>

namespace {

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x10, 4);
  std::memset(sk, 0x20, 4);
  return PQCFUZZ_OK;
}

pqcfuzz_status Encaps(uint8_t *, uint8_t *, const uint8_t *) {
  return PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
  std::memset(ss, 0x40, 4);
  return PQCFUZZ_OK;
}

}  // namespace

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_kem_encaps_fails_adapter() {
  static const pqcfuzz_kem_adapter adapter = {
      "fake", "fake_kem_encaps_fails", "ML-KEM-768", 4, 4, 4, 4, Keygen, Encaps, Decaps};
  return &adapter;
}
