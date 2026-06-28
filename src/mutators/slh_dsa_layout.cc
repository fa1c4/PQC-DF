#include "mutators/slh_dsa_layout.h"

#include <algorithm>

namespace pqcfuzz {
namespace {

constexpr SlhDsaParams kSlhDsaParams[] = {
    {"SLH-DSA-SHA2-128s", 16, 32, 64, 7856, 63, 7, 9, 12, 14},
    {"SLH-DSA-SHAKE-128s", 16, 32, 64, 7856, 63, 7, 9, 12, 14},
    {"SLH-DSA-SHA2-128f", 16, 32, 64, 17088, 66, 22, 3, 6, 33},
    {"SLH-DSA-SHAKE-128f", 16, 32, 64, 17088, 66, 22, 3, 6, 33},
    {"SLH-DSA-SHA2-192s", 24, 48, 96, 16224, 63, 7, 9, 14, 17},
    {"SLH-DSA-SHAKE-192s", 24, 48, 96, 16224, 63, 7, 9, 14, 17},
    {"SLH-DSA-SHA2-192f", 24, 48, 96, 35664, 66, 22, 3, 8, 33},
    {"SLH-DSA-SHAKE-192f", 24, 48, 96, 35664, 66, 22, 3, 8, 33},
    {"SLH-DSA-SHA2-256s", 32, 64, 128, 29792, 64, 8, 8, 14, 22},
    {"SLH-DSA-SHAKE-256s", 32, 64, 128, 29792, 64, 8, 8, 14, 22},
    {"SLH-DSA-SHA2-256f", 32, 64, 128, 49856, 68, 17, 4, 9, 35},
    {"SLH-DSA-SHAKE-256f", 32, 64, 128, 49856, 68, 17, 4, 9, 35},
};

}  // namespace

bool GetSlhDsaParams(const std::string &algorithm, SlhDsaParams *params) {
  for (const auto &candidate : kSlhDsaParams) {
    if (algorithm == candidate.algorithm) {
      if (params != nullptr) {
        *params = candidate;
      }
      return true;
    }
  }
  return false;
}

std::vector<MlKemRegion> SlhDsaSignatureRegions(const SlhDsaParams &params, size_t signature_len) {
  const size_t r_len = std::min(params.n, signature_len);
  const size_t fors_len = params.k * (params.a + 1) * params.n;
  const size_t sigfors_len = std::min(fors_len, signature_len > r_len ? signature_len - r_len : 0);
  const size_t sight_offset = r_len + sigfors_len;
  const size_t sight_len = signature_len > sight_offset ? signature_len - sight_offset : 0;
  const size_t wots_len = std::min<size_t>(67 * params.n * params.d, sight_len);
  const size_t auth_len = sight_len > wots_len ? sight_len - wots_len : 0;
  return {
      {"signature.R", 0, r_len},
      {"signature.SIGFORS", r_len, sigfors_len},
      {"signature.SIGHT", sight_offset, sight_len},
      {"signature.WOTS", sight_offset, wots_len},
      {"signature.XMSS_AUTH_PATH", sight_offset + wots_len, auth_len},
  };
}

std::vector<MlKemRegion> SlhDsaPublicKeyRegions(const SlhDsaParams &params) {
  return {
      {"public_key", 0, params.pk_len},
  };
}

}  // namespace pqcfuzz
