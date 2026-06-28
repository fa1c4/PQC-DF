#include "mutators/ml_dsa_layout.h"

#include <algorithm>

namespace pqcfuzz {
namespace {

constexpr MlDsaParams kMlDsaParams[] = {
    {"ML-DSA-44", 1312, 2560, 2420},
    {"ML-DSA-65", 1952, 4032, 3309},
    {"ML-DSA-87", 2592, 4896, 4627},
};

}  // namespace

bool GetMlDsaParams(const std::string &algorithm, MlDsaParams *params) {
  for (const auto &candidate : kMlDsaParams) {
    if (algorithm == candidate.algorithm) {
      if (params != nullptr) {
        *params = candidate;
      }
      return true;
    }
  }
  return false;
}

std::vector<MlKemRegion> MlDsaSignatureRegions(const MlDsaParams &, size_t signature_len) {
  const size_t c_len = std::min<size_t>(32, signature_len);
  const size_t remaining_after_c = signature_len > c_len ? signature_len - c_len : 0;
  const size_t h_len = std::min<size_t>(96, remaining_after_c);
  const size_t z_len = remaining_after_c > h_len ? remaining_after_c - h_len : 0;
  return {
      {"signature.c", 0, c_len},
      {"signature.z", c_len, z_len},
      {"signature.h", c_len + z_len, h_len},
  };
}

std::vector<MlKemRegion> MlDsaPublicKeyRegions(const MlDsaParams &params) {
  return {
      {"public_key", 0, params.pk_len},
  };
}

}  // namespace pqcfuzz
