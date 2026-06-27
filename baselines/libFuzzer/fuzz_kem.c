#include "fuzz_common.h"

#include <oqs/kem.h>
#include <oqs/oqs.h>
#include <oqs/rand.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	static int initialized = 0;
	if (!initialized) {
		OQS_init();
		initialized = 1;
	}

	const int alg_count = OQS_KEM_alg_count();
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

	const char *algorithm = OQS_KEM_alg_identifier(alg_selector % (uint32_t) alg_count);
	if (algorithm == NULL) {
		return 0;
	}

	OQS_KEM *kem = OQS_KEM_new(algorithm);
	if (kem == NULL) {
		return 0;
	}

	const size_t pk_len = kem->length_public_key;
	const size_t sk_len = kem->length_secret_key;
	const size_t ct_len = kem->length_ciphertext;
	const size_t ss_len = kem->length_shared_secret;

	uint8_t *public_key = pqcdf_alloc(pk_len);
	uint8_t *secret_key = pqcdf_alloc(sk_len);
	uint8_t *ciphertext = pqcdf_alloc(ct_len);
	uint8_t *shared_secret_e = pqcdf_alloc(ss_len);
	uint8_t *shared_secret_d = pqcdf_alloc(ss_len);
	uint8_t *mutated_ciphertext = pqcdf_alloc(ct_len);
	uint8_t *shared_secret_m = pqcdf_alloc(ss_len);

	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_abort_with_message("OQS_KEM_keypair failed");
	}

	rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_abort_with_message("OQS_KEM_encaps failed");
	}

	rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_abort_with_message("OQS_KEM_decaps failed");
	}
	if (memcmp(shared_secret_e, shared_secret_d, ss_len) != 0) {
		pqcdf_abort_with_message("OQS_KEM_decaps produced a mismatched shared secret");
	}

	if (ct_len > 0) {
		memcpy(mutated_ciphertext, ciphertext, ct_len);
		const size_t mutation_len = pqcdf_min_size(payload_size, ct_len);
		if (mutation_len == 0) {
			mutated_ciphertext[0] ^= 0x01;
		} else {
			mutated_ciphertext[0] ^= 0x01;
			for (size_t i = 1; i < mutation_len; i++) {
				mutated_ciphertext[i] ^= (uint8_t) (payload[i] ^ (uint8_t) (i + 1));
			}
		}
		(void) OQS_KEM_decaps(kem, shared_secret_m, mutated_ciphertext, secret_key);
	}

	pqcdf_secure_free(secret_key, sk_len);
	pqcdf_secure_free(shared_secret_e, ss_len);
	pqcdf_secure_free(shared_secret_d, ss_len);
	pqcdf_secure_free(shared_secret_m, ss_len);
	free(public_key);
	free(ciphertext);
	free(mutated_ciphertext);
	OQS_KEM_free(kem);

	return 0;
}
