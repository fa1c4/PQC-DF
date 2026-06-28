#ifndef PQCFUZZ_MUTATORS_ML_KEM_LAYOUT_H
#define PQCFUZZ_MUTATORS_ML_KEM_LAYOUT_H

#include <cstddef>
#include <string>
#include <vector>

namespace pqcfuzz {

struct MlKemParams {
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t ss_len;
  size_t k;
  size_t du;
  size_t dv;
};

struct MlKemRegion {
  std::string name;
  size_t offset;
  size_t length;
};

bool GetMlKemParams(const std::string &algorithm, MlKemParams *params);
std::vector<MlKemRegion> PublicKeyRegions(const MlKemParams &params);
std::vector<MlKemRegion> CiphertextRegions(const MlKemParams &params);

}  // namespace pqcfuzz

#endif
