#include "adapters/adapter_interface.h"

#include <cstring>

namespace {

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  std::memset(pk, 0x10, 4);
  std::memset(sk, 0x20, 4);
  return PQCFUZZ_OK;
}

pqcfuzz_status Sign(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_INVALID_INPUT;
}

pqcfuzz_status Verify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
  return PQCFUZZ_OK;
}

}  // namespace

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_sign_fails_adapter() {
  static const pqcfuzz_sig_adapter adapter = {
      "fake", "fake_sig_sign_fails", "ML-DSA-44", 4, 4, 4, 0, 0, 0, Keygen, Sign, Verify, nullptr};
  return &adapter;
}
