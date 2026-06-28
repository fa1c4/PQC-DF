#ifndef PQCFUZZ_MUTATORS_SLH_DSA_LAYOUT_H
#define PQCFUZZ_MUTATORS_SLH_DSA_LAYOUT_H

#include <cstddef>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

struct SlhDsaParams {
  const char *algorithm;
  size_t n;
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
  size_t h;
  size_t d;
  size_t hp;
  size_t a;
  size_t k;
};

bool GetSlhDsaParams(const std::string &algorithm, SlhDsaParams *params);
std::vector<MlKemRegion> SlhDsaSignatureRegions(const SlhDsaParams &params, size_t signature_len);
std::vector<MlKemRegion> SlhDsaPublicKeyRegions(const SlhDsaParams &params);

}  // namespace pqcfuzz

#endif
