#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {
namespace {

constexpr MlKemParams kMlKemParams[] = {
    {"ML-KEM-512", 800, 1632, 768, 32, 2, 10, 4},
    {"ML-KEM-768", 1184, 2400, 1088, 32, 3, 10, 4},
    {"ML-KEM-1024", 1568, 3168, 1568, 32, 4, 11, 5},
};

}  // namespace

bool GetMlKemParams(const std::string &algorithm, MlKemParams *params) {
  for (const auto &candidate : kMlKemParams) {
    if (algorithm == candidate.algorithm) {
      if (params != nullptr) {
        *params = candidate;
      }
      return true;
    }
  }
  return false;
}

std::vector<MlKemRegion> PublicKeyRegions(const MlKemParams &params) {
  const size_t rho_len = 32;
  const size_t t_len = params.pk_len - rho_len;
  return {
      {"public_key.t", 0, t_len},
      {"public_key.rho", t_len, rho_len},
  };
}

std::vector<MlKemRegion> CiphertextRegions(const MlKemParams &params) {
  const size_t u_len = 32 * params.du * params.k;
  const size_t v_len = 32 * params.dv;
  return {
      {"ciphertext.u", 0, u_len},
      {"ciphertext.v", u_len, v_len},
  };
}

}  // namespace pqcfuzz
