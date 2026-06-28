#ifndef PQCFUZZ_MUTATORS_SLH_DSA_MUTATOR_H
#define PQCFUZZ_MUTATORS_SLH_DSA_MUTATOR_H

#include <cstdint>
#include <vector>

#include "mutators/ml_kem_mutator.h"
#include "mutators/slh_dsa_layout.h"

namespace pqcfuzz {

std::vector<MutationRecord> MutateSlhDsaSignature(
    const SlhDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *signature);
std::vector<MutationRecord> MutateSlhDsaMessage(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *message);
std::vector<MutationRecord> MutateSlhDsaContext(
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *context);
std::vector<MutationRecord> MutateSlhDsaPublicKey(
    const SlhDsaParams &params,
    const std::vector<uint8_t> &mutation_plan,
    std::vector<uint8_t> *public_key);

}  // namespace pqcfuzz

#endif
