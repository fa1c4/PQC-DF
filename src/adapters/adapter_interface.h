#ifndef PQCFUZZ_ADAPTERS_ADAPTER_INTERFACE_H
#define PQCFUZZ_ADAPTERS_ADAPTER_INTERFACE_H

#include <stddef.h>
#include <stdint.h>

#include "adapters/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef pqcfuzz_status (*pqcfuzz_kem_keygen_fn)(uint8_t *pk, uint8_t *sk);
typedef pqcfuzz_status (*pqcfuzz_kem_encaps_fn)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
typedef pqcfuzz_status (*pqcfuzz_kem_decaps_fn)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

typedef pqcfuzz_status (*pqcfuzz_sig_keygen_fn)(uint8_t *pk, uint8_t *sk);
typedef pqcfuzz_status (*pqcfuzz_sig_sign_fn)(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len);
typedef pqcfuzz_status (*pqcfuzz_sig_verify_fn)(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *pk,
    const uint8_t *ctx,
    size_t ctx_len);
typedef pqcfuzz_status (*pqcfuzz_sig_sign_seeded_fn)(
    uint8_t *sig,
    size_t *sig_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sk,
    const uint8_t *ctx,
    size_t ctx_len,
    const uint8_t *seed,
    size_t seed_len);

typedef struct pqcfuzz_kem_adapter {
  const char *project_id;
  const char *implementation_id;
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t ct_len;
  size_t ss_len;
  pqcfuzz_kem_keygen_fn keygen;
  pqcfuzz_kem_encaps_fn encaps;
  pqcfuzz_kem_decaps_fn decaps;
} pqcfuzz_kem_adapter;

typedef struct pqcfuzz_sig_adapter {
  const char *project_id;
  const char *implementation_id;
  const char *algorithm;
  size_t pk_len;
  size_t sk_len;
  size_t sig_max_len;
  int supports_context;
  int supports_seeded_sign;
  int supports_deterministic_sign;
  pqcfuzz_sig_keygen_fn keygen;
  pqcfuzz_sig_sign_fn sign;
  pqcfuzz_sig_verify_fn verify;
  pqcfuzz_sig_sign_seeded_fn sign_seeded;
} pqcfuzz_sig_adapter;

#ifdef __cplusplus
}
#endif

#endif
