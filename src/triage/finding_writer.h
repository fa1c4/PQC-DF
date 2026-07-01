#ifndef PQCFUZZ_TRIAGE_FINDING_WRITER_H
#define PQCFUZZ_TRIAGE_FINDING_WRITER_H

#include <cstdint>
#include <string>
#include <vector>

#include "oracles/oracle_executor.h"

namespace pqcfuzz {

struct FindingArtifactInput {
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string primitive;
  std::string oracle_id;
  std::string result_dir;
  std::string generated_config_json;
  std::vector<uint8_t> structured_input;
  KEMOracleTrace trace;
};

bool WriteFindingArtifacts(const FindingArtifactInput &input, std::string *artifact_dir, std::string *error);

}  // namespace pqcfuzz

#endif
