#ifndef PQCDF_LIBFUZZER_FUZZ_COMMON_H
#define PQCDF_LIBFUZZER_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t *pqcdf_rng_data = NULL;
static size_t pqcdf_rng_size = 0;
static size_t pqcdf_rng_cursor = 0;
static uint64_t pqcdf_rng_state = 0x9e3779b97f4a7c15ULL;

static size_t pqcdf_min_size(size_t a, size_t b) {
	return a < b ? a : b;
}

static uint32_t pqcdf_read_u32(const uint8_t *data, size_t size, size_t offset) {
	uint32_t value = 0;
	for (size_t i = 0; i < 4; i++) {
		if (data != NULL && offset + i < size) {
			value |= ((uint32_t) data[offset + i]) << (8 * i);
		}
	}
	return value;
}

static uint64_t pqcdf_read_u64(const uint8_t *data, size_t size, size_t offset) {
	uint64_t value = 0;
	for (size_t i = 0; i < 8; i++) {
		if (data != NULL && offset + i < size) {
			value |= ((uint64_t) data[offset + i]) << (8 * i);
		}
	}
	return value;
}

static uint64_t pqcdf_next_u64(void) {
	uint64_t x = pqcdf_rng_state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	pqcdf_rng_state = x;
	return x * 0x2545f4914f6cdd1dULL;
}

static void pqcdf_seed_rng(const uint8_t *data, size_t size, uint64_t seed) {
	pqcdf_rng_data = data;
	pqcdf_rng_size = size;
	pqcdf_rng_cursor = 0;
	pqcdf_rng_state = seed ^ 0x9e3779b97f4a7c15ULL;
	if (pqcdf_rng_state == 0) {
		pqcdf_rng_state = 0xd1b54a32d192ed03ULL;
	}
}

static void pqcdf_randombytes(uint8_t *random_array, size_t bytes_to_read) {
	for (size_t i = 0; i < bytes_to_read; i++) {
		uint8_t value = (uint8_t) (pqcdf_next_u64() >> 56);
		if (pqcdf_rng_data != NULL && pqcdf_rng_cursor < pqcdf_rng_size) {
			value ^= pqcdf_rng_data[pqcdf_rng_cursor++];
		}
		random_array[i] = value;
	}
}

static void *pqcdf_alloc(size_t size) {
	void *ptr = calloc(size == 0 ? 1 : size, 1);
	if (ptr == NULL) {
		abort();
	}
	return ptr;
}

static void pqcdf_secure_free(void *ptr, size_t size) {
	if (ptr != NULL) {
		volatile uint8_t *p = (volatile uint8_t *) ptr;
		for (size_t i = 0; i < size; i++) {
			p[i] = 0;
		}
		free(ptr);
	}
}

static void pqcdf_abort_with_message(const char *message) {
	fprintf(stderr, "%s\n", message);
	abort();
}

#endif
