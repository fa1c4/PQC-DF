#ifndef PQCFUZZ_MUTATORS_ML_KEM_MUTATOR_H
#define PQCFUZZ_MUTATORS_ML_KEM_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

struct MutationRecord {
  std::string operation;
  std::string target;
  size_t offset = 0;
  size_t length = 0;
  bool skipped = false;
  std::string reason;
  std::string field_parse_status;
};

std::vector<MutationRecord> MutateMlKemCiphertext(
    const MlKemParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *ciphertext);
std::vector<MutationRecord> MutateMlKemPublicKey(
    const MlKemParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);

}  // namespace pqcfuzz

#endif
