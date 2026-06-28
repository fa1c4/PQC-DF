#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "adapters/liboqs/kem_adapter.h"
#include "adapters/liboqs/sig_adapter.h"
#include "adapters/pqclean/kem_adapter.h"
#include "adapters/pqclean/sig_adapter.h"
#include "mutators/envelope.h"
#include "mutators/ml_dsa_layout.h"
#include "mutators/ml_kem_layout.h"
#include "mutators/slh_dsa_layout.h"
#include "oracles/oracle_executor.h"

namespace {

bool ReadFile(const std::string &path, std::vector<uint8_t> *out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  out->assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  return true;
}

bool WriteFile(const std::string &path, const std::string &text) {
  std::ofstream out(path);
  if (!out) {
    return false;
  }
  out << text;
  return true;
}

std::string ReadTextOrEmpty(const std::string &path) {
  std::ifstream in(path);
  if (!in) {
    return "";
  }
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

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

const pqcfuzz_sig_adapter *LeftSigAdapterFor(const std::string &algorithm) {
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

const pqcfuzz_sig_adapter *RightSigAdapterFor(const std::string &algorithm) {
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

}  // namespace

int main(int argc, char **argv) {
  if (argc != 4) {
    std::cerr << "usage: replay_oracle <generated_config.json> <structured_input.bin> <oracle_trace.json>\n";
    return 2;
  }

  const std::string generated_config_path = argv[1];
  const std::string input_path = argv[2];
  const std::string trace_path = argv[3];
  std::vector<uint8_t> input;
  if (!ReadFile(input_path, &input)) {
    std::cerr << "failed to read input: " << input_path << "\n";
    return 1;
  }

  pqcfuzz::Envelope envelope;
  std::string error;
  if (!pqcfuzz::ParseEnvelope(input.data(), input.size(), &envelope, &error)) {
    std::cerr << "failed to parse PQCFuzz envelope: " << error << "\n";
    return 1;
  }

  const std::string algorithm = pqcfuzz::AlgorithmName(envelope.algorithm);
  pqcfuzz::MlDsaParams dsa_params{};
  pqcfuzz::SlhDsaParams slh_params{};
  const bool is_mldsa = pqcfuzz::GetMlDsaParams(algorithm, &dsa_params);
  const bool is_slhdsa = pqcfuzz::GetSlhDsaParams(algorithm, &slh_params);
  if (is_mldsa || is_slhdsa) {
    pqcfuzz::SigOracleExecutorConfig config;
    config.job_id = "replay_oracle";
    config.pair_id = "replay_pair";
    config.algorithm = algorithm;
    config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
    config.params = dsa_params;
    config.slh_params = slh_params;
    config.is_slh_dsa = is_slhdsa;
    config.left = LeftSigAdapterFor(algorithm);
    config.right = RightSigAdapterFor(algorithm);
    config.exchange_contract.public_key_exchange = true;
    config.exchange_contract.signature_exchange = true;
    config.seed = envelope.seed;
    config.message = envelope.msg.empty() ? std::vector<uint8_t>{'P', 'Q', 'C', 'F', 'u', 'z', 'z'} : envelope.msg;
    config.context = envelope.extra.size() > 255 ? std::vector<uint8_t>(envelope.extra.begin(), envelope.extra.begin() + 255) : envelope.extra;
    config.mutation = envelope.mutation;
    (void)ReadTextOrEmpty(generated_config_path);

    const pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteSigOracle(config);
    if (!WriteFile(trace_path, pqcfuzz::TraceToJson(trace))) {
      std::cerr << "failed to write trace: " << trace_path << "\n";
      return 1;
    }
    return trace.findings.empty() ? 0 : 3;
  }

  pqcfuzz::MlKemParams params{};
  if (!pqcfuzz::GetMlKemParams(algorithm, &params)) {
    std::cerr << "unsupported ML-KEM algorithm: " << algorithm << "\n";
    return 1;
  }

  pqcfuzz::OracleExecutorConfig config;
  config.job_id = "replay_oracle";
  config.pair_id = "replay_pair";
  config.algorithm = algorithm;
  config.oracle_id = pqcfuzz::OracleName(envelope.oracle_id);
  config.params = params;
  config.left = LeftAdapterFor(algorithm);
  config.right = RightAdapterFor(algorithm);
  config.exchange_contract = {true, true, true};
  config.seed = envelope.seed;
  config.mutation = envelope.mutation;
  (void)ReadTextOrEmpty(generated_config_path);

  const pqcfuzz::KEMOracleTrace trace = pqcfuzz::ExecuteKemOracle(config);
  if (!WriteFile(trace_path, pqcfuzz::TraceToJson(trace))) {
    std::cerr << "failed to write trace: " << trace_path << "\n";
    return 1;
  }
  return trace.findings.empty() ? 0 : 3;
}
