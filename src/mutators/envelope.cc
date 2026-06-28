#include "mutators/envelope.h"

#include <cstring>

namespace pqcfuzz {
namespace {

bool ReadU16(const uint8_t *data, size_t size, size_t *offset, uint16_t *value) {
  if (*offset + 2 > size) {
    return false;
  }
  *value = static_cast<uint16_t>(data[*offset]) | static_cast<uint16_t>(data[*offset + 1] << 8);
  *offset += 2;
  return true;
}

bool ReadSlice(const uint8_t *data, size_t size, size_t *offset, uint16_t length, std::vector<uint8_t> *out) {
  if (*offset + length > size) {
    return false;
  }
  out->assign(data + *offset, data + *offset + length);
  *offset += length;
  return true;
}

}  // namespace

const char *AlgorithmName(AlgorithmId algorithm) {
  switch (algorithm) {
    case AlgorithmId::kMlKem512:
      return "ML-KEM-512";
    case AlgorithmId::kMlKem768:
      return "ML-KEM-768";
    case AlgorithmId::kMlKem1024:
      return "ML-KEM-1024";
    case AlgorithmId::kMlDsa44:
      return "ML-DSA-44";
    case AlgorithmId::kMlDsa65:
      return "ML-DSA-65";
    case AlgorithmId::kMlDsa87:
      return "ML-DSA-87";
    case AlgorithmId::kSlhDsaSha2_128s:
      return "SLH-DSA-SHA2-128s";
    case AlgorithmId::kSlhDsaShake_128s:
      return "SLH-DSA-SHAKE-128s";
    case AlgorithmId::kSlhDsaSha2_128f:
      return "SLH-DSA-SHA2-128f";
    case AlgorithmId::kSlhDsaShake_128f:
      return "SLH-DSA-SHAKE-128f";
    case AlgorithmId::kSlhDsaSha2_192s:
      return "SLH-DSA-SHA2-192s";
    case AlgorithmId::kSlhDsaShake_192s:
      return "SLH-DSA-SHAKE-192s";
    case AlgorithmId::kSlhDsaSha2_192f:
      return "SLH-DSA-SHA2-192f";
    case AlgorithmId::kSlhDsaShake_192f:
      return "SLH-DSA-SHAKE-192f";
    case AlgorithmId::kSlhDsaSha2_256s:
      return "SLH-DSA-SHA2-256s";
    case AlgorithmId::kSlhDsaShake_256s:
      return "SLH-DSA-SHAKE-256s";
    case AlgorithmId::kSlhDsaSha2_256f:
      return "SLH-DSA-SHA2-256f";
    case AlgorithmId::kSlhDsaShake_256f:
      return "SLH-DSA-SHAKE-256f";
    case AlgorithmId::kUnknown:
      return "UNKNOWN";
  }
  return "UNKNOWN";
}

const char *OracleName(OracleId oracle_id) {
  switch (oracle_id) {
    case OracleId::kMlKemLocalRoundtrip:
      return "mlkem_local_roundtrip";
    case OracleId::kMlKemCrossExchangeRoundtrip:
      return "mlkem_cross_exchange_roundtrip";
    case OracleId::kMlKemTamperedCiphertextImplicitRejection:
      return "mlkem_tampered_ciphertext_implicit_rejection";
    case OracleId::kMlKemBadRandomnessSanity:
      return "mlkem_bad_randomness_sanity";
    case OracleId::kMlDsaLocalSignVerify:
      return "mldsa_local_sign_verify";
    case OracleId::kMlDsaCrossVerify:
      return "mldsa_cross_verify";
    case OracleId::kMlDsaMutatedSignatureNegative:
      return "mldsa_mutated_signature_negative";
    case OracleId::kMlDsaMutatedMessageNegative:
      return "mldsa_mutated_message_negative";
    case OracleId::kMlDsaMutatedContextNegative:
      return "mldsa_mutated_context_negative";
    case OracleId::kMlDsaOidFieldMutationSanity:
      return "mldsa_oid_field_mutation_sanity";
    case OracleId::kMlDsaBadRandomnessSanity:
      return "mldsa_bad_randomness_sanity";
    case OracleId::kSlhDsaLocalSignVerify:
      return "slhdsa_local_sign_verify";
    case OracleId::kSlhDsaCrossVerify:
      return "slhdsa_cross_verify";
    case OracleId::kSlhDsaMutatedSignatureNegative:
      return "slhdsa_mutated_signature_negative";
    case OracleId::kSlhDsaMutatedMessageNegative:
      return "slhdsa_mutated_message_negative";
    case OracleId::kSlhDsaMutatedContextNegative:
      return "slhdsa_mutated_context_negative";
    case OracleId::kSlhDsaBadRandomnessSanity:
      return "slhdsa_bad_randomness_sanity";
    case OracleId::kUnknown:
      return "unknown";
  }
  return "unknown";
}

AlgorithmId AlgorithmIdFromName(const std::string &name) {
  if (name == "ML-KEM-512") {
    return AlgorithmId::kMlKem512;
  }
  if (name == "ML-KEM-768") {
    return AlgorithmId::kMlKem768;
  }
  if (name == "ML-KEM-1024") {
    return AlgorithmId::kMlKem1024;
  }
  if (name == "ML-DSA-44") {
    return AlgorithmId::kMlDsa44;
  }
  if (name == "ML-DSA-65") {
    return AlgorithmId::kMlDsa65;
  }
  if (name == "ML-DSA-87") {
    return AlgorithmId::kMlDsa87;
  }
  if (name == "SLH-DSA-SHA2-128s") {
    return AlgorithmId::kSlhDsaSha2_128s;
  }
  if (name == "SLH-DSA-SHAKE-128s") {
    return AlgorithmId::kSlhDsaShake_128s;
  }
  if (name == "SLH-DSA-SHA2-128f") {
    return AlgorithmId::kSlhDsaSha2_128f;
  }
  if (name == "SLH-DSA-SHAKE-128f") {
    return AlgorithmId::kSlhDsaShake_128f;
  }
  if (name == "SLH-DSA-SHA2-192s") {
    return AlgorithmId::kSlhDsaSha2_192s;
  }
  if (name == "SLH-DSA-SHAKE-192s") {
    return AlgorithmId::kSlhDsaShake_192s;
  }
  if (name == "SLH-DSA-SHA2-192f") {
    return AlgorithmId::kSlhDsaSha2_192f;
  }
  if (name == "SLH-DSA-SHAKE-192f") {
    return AlgorithmId::kSlhDsaShake_192f;
  }
  if (name == "SLH-DSA-SHA2-256s") {
    return AlgorithmId::kSlhDsaSha2_256s;
  }
  if (name == "SLH-DSA-SHAKE-256s") {
    return AlgorithmId::kSlhDsaShake_256s;
  }
  if (name == "SLH-DSA-SHA2-256f") {
    return AlgorithmId::kSlhDsaSha2_256f;
  }
  if (name == "SLH-DSA-SHAKE-256f") {
    return AlgorithmId::kSlhDsaShake_256f;
  }
  return AlgorithmId::kUnknown;
}

OracleId OracleIdFromName(const std::string &name) {
  if (name == "mlkem_local_roundtrip") {
    return OracleId::kMlKemLocalRoundtrip;
  }
  if (name == "mlkem_cross_exchange_roundtrip") {
    return OracleId::kMlKemCrossExchangeRoundtrip;
  }
  if (name == "mlkem_tampered_ciphertext_implicit_rejection") {
    return OracleId::kMlKemTamperedCiphertextImplicitRejection;
  }
  if (name == "mlkem_bad_randomness_sanity") {
    return OracleId::kMlKemBadRandomnessSanity;
  }
  if (name == "mldsa_local_sign_verify") {
    return OracleId::kMlDsaLocalSignVerify;
  }
  if (name == "mldsa_cross_verify") {
    return OracleId::kMlDsaCrossVerify;
  }
  if (name == "mldsa_mutated_signature_negative") {
    return OracleId::kMlDsaMutatedSignatureNegative;
  }
  if (name == "mldsa_mutated_message_negative") {
    return OracleId::kMlDsaMutatedMessageNegative;
  }
  if (name == "mldsa_mutated_context_negative") {
    return OracleId::kMlDsaMutatedContextNegative;
  }
  if (name == "mldsa_oid_field_mutation_sanity") {
    return OracleId::kMlDsaOidFieldMutationSanity;
  }
  if (name == "mldsa_bad_randomness_sanity") {
    return OracleId::kMlDsaBadRandomnessSanity;
  }
  if (name == "slhdsa_local_sign_verify") {
    return OracleId::kSlhDsaLocalSignVerify;
  }
  if (name == "slhdsa_cross_verify") {
    return OracleId::kSlhDsaCrossVerify;
  }
  if (name == "slhdsa_mutated_signature_negative") {
    return OracleId::kSlhDsaMutatedSignatureNegative;
  }
  if (name == "slhdsa_mutated_message_negative") {
    return OracleId::kSlhDsaMutatedMessageNegative;
  }
  if (name == "slhdsa_mutated_context_negative") {
    return OracleId::kSlhDsaMutatedContextNegative;
  }
  if (name == "slhdsa_bad_randomness_sanity") {
    return OracleId::kSlhDsaBadRandomnessSanity;
  }
  return OracleId::kUnknown;
}

bool ParseEnvelope(const uint8_t *data, size_t size, Envelope *envelope, std::string *error) {
  if (envelope == nullptr) {
    return false;
  }
  if (size < 8) {
    if (error != nullptr) {
      *error = "input shorter than PQCFuzz envelope header";
    }
    return false;
  }
  if (std::memcmp(data, "PQCF", 4) != 0) {
    if (error != nullptr) {
      *error = "bad PQCFuzz envelope magic";
    }
    return false;
  }

  Envelope parsed;
  parsed.version = data[4];
  parsed.algorithm = static_cast<AlgorithmId>(data[5]);
  parsed.oracle_id = static_cast<OracleId>(data[6]);
  parsed.flags = data[7];
  size_t offset = 8;

  uint16_t seed_len = 0;
  uint16_t msg_len = 0;
  uint16_t mutation_len = 0;
  uint16_t extra_len = 0;
  if (!ReadU16(data, size, &offset, &seed_len) || !ReadSlice(data, size, &offset, seed_len, &parsed.seed) ||
      !ReadU16(data, size, &offset, &msg_len) || !ReadSlice(data, size, &offset, msg_len, &parsed.msg) ||
      !ReadU16(data, size, &offset, &mutation_len) ||
      !ReadSlice(data, size, &offset, mutation_len, &parsed.mutation) ||
      !ReadU16(data, size, &offset, &extra_len) || !ReadSlice(data, size, &offset, extra_len, &parsed.extra)) {
    if (error != nullptr) {
      *error = "truncated PQCFuzz envelope field";
    }
    return false;
  }
  if (offset != size) {
    if (error != nullptr) {
      *error = "trailing bytes after PQCFuzz envelope";
    }
    return false;
  }
  if (parsed.version != 1) {
    if (error != nullptr) {
      *error = "unsupported PQCFuzz envelope version";
    }
    return false;
  }
  if (parsed.algorithm == AlgorithmId::kUnknown || parsed.oracle_id == OracleId::kUnknown) {
    if (error != nullptr) {
      *error = "unknown algorithm or oracle enum";
    }
    return false;
  }

  *envelope = std::move(parsed);
  return true;
}

}  // namespace pqcfuzz
