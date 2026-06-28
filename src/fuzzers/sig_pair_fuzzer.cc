#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "adapters/liboqs/sig_adapter.h"
#include "adapters/pqclean/sig_adapter.h"
#include "mutators/envelope.h"
#include "mutators/ml_dsa_layout.h"
#include "mutators/slh_dsa_layout.h"
#include "oracles/oracle_executor.h"
#include "triage/finding_writer.h"

#ifndef PQCFUZZ_JOB_ID
#define PQCFUZZ_JOB_ID "adhoc_pqcfuzz_sig_job"
#endif

#ifndef PQCFUZZ_PAIR_ID
#define PQCFUZZ_PAIR_ID "adhoc_liboqs_vs_pqclean_sig"
#endif

#ifndef PQCFUZZ_RESULT_DIR
#define PQCFUZZ_RESULT_DIR "workspace/results/adhoc_pqcfuzz_sig_job"
#endif

#ifndef PQCFUZZ_GENERATED_CONFIG_PATH
#define PQCFUZZ_GENERATED_CONFIG_PATH ""
#endif

namespace {

const pqcfuzz_sig_adapter *LeftAdapterFor(const std::string &algorithm) {
  if (algorithm == "ML-DSA-44") {
    return pqcfuzz_get_liboqs_mldsa44_adapter();
  }
  if (algorithm == "ML-DSA-65") {
    return pqcfuzz_get_liboqs_mldsa65_adapter();
  }
  if (algorithm == "ML-DSA-87") {
    return pqcfuzz_get_liboqs_mldsa87_adapter();
  }
  if (algorithm == "SLH-DSA-SHA2-128s") return pqcfuzz_get_liboqs_slhdsa_sha2_128s_adapter();
  if (algorithm == "SLH-DSA-SHAKE-128s") return pqcfuzz_get_liboqs_slhdsa_shake_128s_adapter();
  if (algorithm == "SLH-DSA-SHA2-128f") return pqcfuzz_get_liboqs_slhdsa_sha2_128f_adapter();
  if (algorithm == "SLH-DSA-SHAKE-128f") return pqcfuzz_get_liboqs_slhdsa_shake_128f_adapter();
  if (algorithm == "SLH-DSA-SHA2-192s") return pqcfuzz_get_liboqs_slhdsa_sha2_192s_adapter();
  if (algorithm == "SLH-DSA-SHAKE-192s") return pqcfuzz_get_liboqs_slhdsa_shake_192s_adapter();
  if (algorithm == "SLH-DSA-SHA2-192f") return pqcfuzz_get_liboqs_slhdsa_sha2_192f_adapter();
  if (algorithm == "SLH-DSA-SHAKE-192f") return pqcfuzz_get_liboqs_slhdsa_shake_192f_adapter();
  if (algorithm == "SLH-DSA-SHA2-256s") return pqcfuzz_get_liboqs_slhdsa_sha2_256s_adapter();
  if (algorithm == "SLH-DSA-SHAKE-256s") return pqcfuzz_get_liboqs_slhdsa_shake_256s_adapter();
  if (algorithm == "SLH-DSA-SHA2-256f") return pqcfuzz_get_liboqs_slhdsa_sha2_256f_adapter();
  if (algorithm == "SLH-DSA-SHAKE-256f") return pqcfuzz_get_liboqs_slhdsa_shake_256f_adapter();
  return nullptr;
}

const pqcfuzz_sig_adapter *RightAdapterFor(const std::string &algorithm) {
  if (algorithm == "ML-DSA-44") {
    return pqcfuzz_get_pqclean_mldsa44_adapter();
  }
  if (algorithm == "ML-DSA-65") {
    return pqcfuzz_get_pqclean_mldsa65_adapter();
  }
  if (algorithm == "ML-DSA-87") {
    return pqcfuzz_get_pqclean_mldsa87_adapter();
  }
  if (algorithm == "SLH-DSA-SHA2-128s") return pqcfuzz_get_pqclean_slhdsa_sha2_128s_adapter();
  if (algorithm == "SLH-DSA-SHAKE-128s") return pqcfuzz_get_pqclean_slhdsa_shake_128s_adapter();
  if (algorithm == "SLH-DSA-SHA2-128f") return pqcfuzz_get_pqclean_slhdsa_sha2_128f_adapter();
  if (algorithm == "SLH-DSA-SHAKE-128f") return pqcfuzz_get_pqclean_slhdsa_shake_128f_adapter();
  if (algorithm == "SLH-DSA-SHA2-192s") return pqcfuzz_get_pqclean_slhdsa_sha2_192s_adapter();
  if (algorithm == "SLH-DSA-SHAKE-192s") return pqcfuzz_get_pqclean_slhdsa_shake_192s_adapter();
  if (algorithm == "SLH-DSA-SHA2-192f") return pqcfuzz_get_pqclean_slhdsa_sha2_192f_adapter();
  if (algorithm == "SLH-DSA-SHAKE-192f") return pqcfuzz_get_pqclean_slhdsa_shake_192f_adapter();
  if (algorithm == "SLH-DSA-SHA2-256s") return pqcfuzz_get_pqclean_slhdsa_sha2_256s_adapter();
  if (algorithm == "SLH-DSA-SHAKE-256s") return pqcfuzz_get_pqclean_slhdsa_shake_256s_adapter();
  if (algorithm == "SLH-DSA-SHA2-256f") return pqcfuzz_get_pqclean_slhdsa_sha2_256f_adapter();
  if (algorithm == "SLH-DSA-SHAKE-256f") return pqcfuzz_get_pqclean_slhdsa_shake_256f_adapter();
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
  pqcfuzz::MlDsaParams params{};
  pqcfuzz::SlhDsaParams slh_params{};
  const bool is_mldsa = pqcfuzz::GetMlDsaParams(algorithm, &params);
  const bool is_slhdsa = pqcfuzz::GetSlhDsaParams(algorithm, &slh_params);
  if (!is_mldsa && !is_slhdsa) {
    return 0;
  }

  pqcfuzz::SigOracleExecutorConfig config;
  config.job_id = PQCFUZZ_JOB_ID;
  config.pair_id = PQCFUZZ_PAIR_ID;
  config.algorithm = algorithm;
  config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
  config.params = params;
  config.slh_params = slh_params;
  config.is_slh_dsa = is_slhdsa;
  config.left = LeftAdapterFor(algorithm);
  config.right = RightAdapterFor(algorithm);
  config.exchange_contract.public_key_exchange = true;
  config.exchange_contract.signature_exchange = true;
  config.seed = envelope.seed;
  config.message = envelope.msg.empty() ? std::vector<uint8_t>{'P', 'Q', 'C', 'F', 'u', 'z', 'z'} : envelope.msg;
  config.context = envelope.extra.size() > 255 ? std::vector<uint8_t>(envelope.extra.begin(), envelope.extra.begin() + 255) : envelope.extra;
  config.mutation = envelope.mutation;

  pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteSigOracle(config);
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
