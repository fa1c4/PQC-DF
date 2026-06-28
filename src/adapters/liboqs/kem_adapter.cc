#include "adapters/liboqs/kem_adapter.h"

#include <cstring>

#ifdef PQCFUZZ_HAVE_LIBOQS
extern "C" {
int OQS_KEM_ml_kem_512_keypair(uint8_t *public_key, uint8_t *secret_key);
int OQS_KEM_ml_kem_512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
int OQS_KEM_ml_kem_512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
int OQS_KEM_ml_kem_768_keypair(uint8_t *public_key, uint8_t *secret_key);
int OQS_KEM_ml_kem_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
int OQS_KEM_ml_kem_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
int OQS_KEM_ml_kem_1024_keypair(uint8_t *public_key, uint8_t *secret_key);
int OQS_KEM_ml_kem_1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
int OQS_KEM_ml_kem_1024_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
}
#endif

namespace {

pqcfuzz_status UnsupportedKeygen(uint8_t *, uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}

pqcfuzz_status UnsupportedEncaps(uint8_t *, uint8_t *, const uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}

pqcfuzz_status UnsupportedDecaps(uint8_t *, const uint8_t *, const uint8_t *) {
  return PQCFUZZ_API_UNSUPPORTED;
}

#ifdef PQCFUZZ_HAVE_LIBOQS
pqcfuzz_status MlKem512Keygen(uint8_t *pk, uint8_t *sk) {
  return pqcfuzz_normalize_return_code(OQS_KEM_ml_kem_512_keypair(pk, sk));
}
pqcfuzz_status MlKem512Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  return pqcfuzz_normalize_return_code(OQS_KEM_ml_kem_512_encaps(ct, ss, pk));
}
pqcfuzz_status MlKem512Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  return pqcfuzz_normalize_return_code(OQS_KEM_ml_kem_512_decaps(ss, ct, sk));
}
pqcfuzz_status MlKem768Keygen(uint8_t *pk, uint8_t *sk) {
  return pqcfuzz_normalize_return_code(OQS_KEM_ml_kem_768_keypair(pk, sk));
}
pqcfuzz_status MlKem768Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  return pqcfuzz_normalize_return_code(OQS_KEM_ml_kem_768_encaps(ct, ss, pk));
}
pqcfuzz_status MlKem768Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  return pqcfuzz_normalize_return_code(OQS_KEM_ml_kem_768_decaps(ss, ct, sk));
}
pqcfuzz_status MlKem1024Keygen(uint8_t *pk, uint8_t *sk) {
  return pqcfuzz_normalize_return_code(OQS_KEM_ml_kem_1024_keypair(pk, sk));
}
pqcfuzz_status MlKem1024Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  return pqcfuzz_normalize_return_code(OQS_KEM_ml_kem_1024_encaps(ct, ss, pk));
}
pqcfuzz_status MlKem1024Decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  return pqcfuzz_normalize_return_code(OQS_KEM_ml_kem_1024_decaps(ss, ct, sk));
}
#else
#define MlKem512Keygen UnsupportedKeygen
#define MlKem512Encaps UnsupportedEncaps
#define MlKem512Decaps UnsupportedDecaps
#define MlKem768Keygen UnsupportedKeygen
#define MlKem768Encaps UnsupportedEncaps
#define MlKem768Decaps UnsupportedDecaps
#define MlKem1024Keygen UnsupportedKeygen
#define MlKem1024Encaps UnsupportedEncaps
#define MlKem1024Decaps UnsupportedDecaps
#endif

const pqcfuzz_kem_adapter kMlKem512 = {
    "liboqs",
    "liboqs_mlkem512_wrapper_generic",
    "ML-KEM-512",
    800,
    1632,
    768,
    32,
    MlKem512Keygen,
    MlKem512Encaps,
    MlKem512Decaps,
};

const pqcfuzz_kem_adapter kMlKem768 = {
    "liboqs",
    "liboqs_mlkem768_wrapper_generic",
    "ML-KEM-768",
    1184,
    2400,
    1088,
    32,
    MlKem768Keygen,
    MlKem768Encaps,
    MlKem768Decaps,
};

const pqcfuzz_kem_adapter kMlKem1024 = {
    "liboqs",
    "liboqs_mlkem1024_wrapper_generic",
    "ML-KEM-1024",
    1568,
    3168,
    1568,
    32,
    MlKem1024Keygen,
    MlKem1024Encaps,
    MlKem1024Decaps,
};

}  // namespace

const pqcfuzz_kem_adapter *pqcfuzz_get_liboqs_mlkem512_adapter(void) {
  return &kMlKem512;
}

const pqcfuzz_kem_adapter *pqcfuzz_get_liboqs_mlkem768_adapter(void) {
  return &kMlKem768;
}

const pqcfuzz_kem_adapter *pqcfuzz_get_liboqs_mlkem1024_adapter(void) {
  return &kMlKem1024;
}

const pqcfuzz_kem_adapter *pqcfuzz_get_liboqs_adapter(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  if (std::strcmp(implementation_id, kMlKem512.implementation_id) == 0) {
    return &kMlKem512;
  }
  if (std::strcmp(implementation_id, kMlKem768.implementation_id) == 0) {
    return &kMlKem768;
  }
  if (std::strcmp(implementation_id, kMlKem1024.implementation_id) == 0) {
    return &kMlKem1024;
  }
  return nullptr;
}
