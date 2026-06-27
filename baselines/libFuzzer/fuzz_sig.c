#include "fuzz_common.h"

#include <oqs/oqs.h>
#include <oqs/rand.h>
#include <oqs/sig.h>

#define PQCDF_MAX_SIG_MESSAGE_LEN 4096

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	static int initialized = 0;
	static const uint8_t empty_message = 0;
	if (!initialized) {
		OQS_init();
		initialized = 1;
	}

	const int alg_count = OQS_SIG_alg_count();
	if (alg_count <= 0) {
		return 0;
	}

	const uint32_t alg_selector = pqcdf_read_u32(data, size, 0);
	const uint64_t rng_seed = pqcdf_read_u64(data, size, 4);
	const size_t payload_offset = size > 12 ? 12 : size;
	const uint8_t *payload = (data != NULL && payload_offset < size) ? data + payload_offset : NULL;
	const size_t payload_size = size - payload_offset;

	pqcdf_seed_rng(payload, payload_size, rng_seed ^ alg_selector);
	OQS_randombytes_custom_algorithm(&pqcdf_randombytes);

	const char *algorithm = OQS_SIG_alg_identifier(alg_selector % (uint32_t) alg_count);
	if (algorithm == NULL) {
		return 0;
	}

	OQS_SIG *sig = OQS_SIG_new(algorithm);
	if (sig == NULL) {
		return 0;
	}

	const size_t pk_len = sig->length_public_key;
	const size_t sk_len = sig->length_secret_key;
	const size_t max_sig_len = sig->length_signature;
	const size_t message_len = pqcdf_min_size(payload_size, PQCDF_MAX_SIG_MESSAGE_LEN);
	const uint8_t *message = message_len == 0 ? &empty_message : payload;

	uint8_t *public_key = pqcdf_alloc(pk_len);
	uint8_t *secret_key = pqcdf_alloc(sk_len);
	uint8_t *signature = pqcdf_alloc(max_sig_len);
	uint8_t *mutated_signature = pqcdf_alloc(max_sig_len);
	size_t signature_len = 0;

	OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_abort_with_message("OQS_SIG_keypair failed");
	}

	rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_abort_with_message("OQS_SIG_sign failed");
	}
	if (signature_len > max_sig_len) {
		pqcdf_abort_with_message("OQS_SIG_sign returned an oversized signature length");
	}

	rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_abort_with_message("OQS_SIG_verify rejected a freshly generated signature");
	}

	if (signature_len > 0) {
		memcpy(mutated_signature, signature, signature_len);
		const size_t mutation_len = pqcdf_min_size(payload_size, signature_len);
		if (mutation_len == 0) {
			mutated_signature[0] ^= 0x01;
		} else {
			mutated_signature[0] ^= 0x01;
			for (size_t i = 1; i < mutation_len; i++) {
				mutated_signature[i] ^= (uint8_t) (payload[i] ^ (uint8_t) (i + 1));
			}
		}
		(void) OQS_SIG_verify(sig, message, message_len, mutated_signature, signature_len, public_key);
	}

	free(public_key);
	pqcdf_secure_free(secret_key, sk_len);
	free(signature);
	free(mutated_signature);
	OQS_SIG_free(sig);

	return 0;
}
