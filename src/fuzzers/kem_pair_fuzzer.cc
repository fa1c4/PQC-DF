#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "adapters/liboqs/kem_adapter.h"
#include "adapters/pqclean/kem_adapter.h"
#include "mutators/envelope.h"
#include "mutators/ml_kem_layout.h"
#include "oracles/oracle_executor.h"
#include "triage/finding_writer.h"

#ifndef PQCFUZZ_JOB_ID
#define PQCFUZZ_JOB_ID "adhoc_pqcfuzz_kem_job"
#endif

#ifndef PQCFUZZ_PAIR_ID
#define PQCFUZZ_PAIR_ID "adhoc_liboqs_vs_pqclean"
#endif

#ifndef PQCFUZZ_RESULT_DIR
#define PQCFUZZ_RESULT_DIR "workspace/results/adhoc_pqcfuzz_kem_job"
#endif

#ifndef PQCFUZZ_GENERATED_CONFIG_PATH
#define PQCFUZZ_GENERATED_CONFIG_PATH ""
#endif

namespace {

const pqcfuzz_kem_adapter *LeftAdapterFor(const std::string &algorithm) {
  if (algorithm == "ML-KEM-512") {
    return pqcfuzz_get_liboqs_mlkem512_adapter();
  }
  if (algorithm == "ML-KEM-768") {
    return pqcfuzz_get_liboqs_mlkem768_adapter();
  }
  if (algorithm == "ML-KEM-1024") {
    return pqcfuzz_get_liboqs_mlkem1024_adapter();
  }
  return nullptr;
}

const pqcfuzz_kem_adapter *RightAdapterFor(const std::string &algorithm) {
  if (algorithm == "ML-KEM-512") {
    return pqcfuzz_get_pqclean_mlkem512_adapter();
  }
  if (algorithm == "ML-KEM-768") {
    return pqcfuzz_get_pqclean_mlkem768_adapter();
  }
  if (algorithm == "ML-KEM-1024") {
    return pqcfuzz_get_pqclean_mlkem1024_adapter();
  }
  return nullptr;
}

std::string ReadConfigText() {
  if (std::string(PQCFUZZ_GENERATED_CONFIG_PATH).empty()) {
    return "{}\n";
  }
  std::ifstream in(PQCFUZZ_GENERATED_CONFIG_PATH);
  if (!in) {
    return "{}\n";
  }
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pqcfuzz::Envelope envelope;
  std::string error;
  if (!pqcfuzz::ParseEnvelope(data, size, &envelope, &error)) {
    return 0;
  }

  const std::string algorithm = pqcfuzz::AlgorithmName(envelope.algorithm);
  pqcfuzz::MlKemParams params{};
  if (!pqcfuzz::GetMlKemParams(algorithm, &params)) {
    return 0;
  }

  pqcfuzz::OracleExecutorConfig config;
  config.job_id = PQCFUZZ_JOB_ID;
  config.pair_id = PQCFUZZ_PAIR_ID;
  config.algorithm = algorithm;
  config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
  config.params = params;
  config.left = LeftAdapterFor(algorithm);
  config.right = RightAdapterFor(algorithm);
  config.exchange_contract = {true, true, true};
  config.seed = envelope.seed;
  config.mutation = envelope.mutation;

  pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteKemOracle(config);
  if (!trace.findings.empty()) {
    pqcfuzz::FindingArtifactInput artifacts;
    artifacts.job_id = config.job_id;
    artifacts.pair_id = config.pair_id;
    artifacts.algorithm = config.algorithm;
    artifacts.oracle_id = config.oracle_id;
    artifacts.result_dir = PQCFUZZ_RESULT_DIR;
    artifacts.generated_config_json = ReadConfigText();
    artifacts.structured_input.assign(data, data + size);
    artifacts.trace = trace;
    std::string artifact_dir;
    pqcfuzz::WriteFindingArtifacts(artifacts, &artifact_dir, nullptr);
  }
  return 0;
}
