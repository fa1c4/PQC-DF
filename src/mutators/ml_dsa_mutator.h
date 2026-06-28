#ifndef PQCFUZZ_MUTATORS_ML_DSA_MUTATOR_H
#define PQCFUZZ_MUTATORS_ML_DSA_MUTATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_dsa_layout.h"
#include "mutators/ml_kem_mutator.h"

namespace pqcfuzz {

std::vector<MutationRecord> MutateMlDsaSignature(
    const MlDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature);
std::vector<MutationRecord> MutateMlDsaMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message);
std::vector<MutationRecord> MutateMlDsaContext(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *context);
std::vector<MutationRecord> MutateMlDsaOid(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *oid);
std::vector<MutationRecord> MutateMlDsaPublicKey(
    const MlDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);

}  // namespace pqcfuzz

#endif
