#ifndef PQCFUZZ_MUTATORS_ML_DSA_LAYOUT_H
#define PQCFUZZ_MUTATORS_ML_DSA_LAYOUT_H

#include <cstddef>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

struct MlDsaParams {
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
};

bool GetMlDsaParams(const std::string &algorithm, MlDsaParams *params);
std::vector<MlKemRegion> MlDsaSignatureRegions(const MlDsaParams &params, size_t signature_len);
std::vector<MlKemRegion> MlDsaPublicKeyRegions(const MlDsaParams &params);

}  // namespace pqcfuzz

#endif
