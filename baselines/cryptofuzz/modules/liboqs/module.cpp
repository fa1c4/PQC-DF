#include "module.h"

#include <cryptofuzz/util.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <oqs/oqs.h>
#include <string>
#include <vector>

namespace cryptofuzz {
namespace module {

namespace {

static uint64_t rngState = 0;

uint64_t Mix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

void DeterministicRandomBytes(uint8_t *out, size_t outLen) {
    size_t off = 0;
    while ( off < outLen ) {
        rngState = Mix64(rngState);
        const uint64_t block = rngState;
        const size_t n = std::min(outLen - off, sizeof(block));
        std::memcpy(out + off, &block, n);
        off += n;
    }
}

void SetDeterministicRandom(const std::vector<uint8_t>& entropy, uint64_t selector, const char *domain) {
    uint64_t state = 0x6a09e667f3bcc909ULL ^ selector;

    for (const auto byte : entropy) {
        state ^= byte;
        state *= 0x100000001b3ULL;
    }
    for (const char *p = domain; *p != '\0'; p++) {
        state ^= static_cast<uint8_t>(*p);
        state *= 0x100000001b3ULL;
    }

    rngState = Mix64(state);
    OQS_randombytes_custom_algorithm(DeterministicRandomBytes);
}

bool Mutate(std::vector<uint8_t>& data, const Buffer& mutation, uint64_t selector) {
    if ( data.empty() ) {
        return false;
    }

    const auto mutationBytes = mutation.Get();
    const size_t pos = static_cast<size_t>(selector % data.size());
    uint8_t delta = 1;

    if ( !mutationBytes.empty() ) {
        delta = mutationBytes[static_cast<size_t>(selector % mutationBytes.size())] | 1;
    }

    data[pos] ^= delta;
    return true;
}

bool VectorsEqual(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs) {
    return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

bool Fail(const char *kind, const std::string& algorithm, const char *reason) {
    std::printf("[liboqs] %s %s: %s\n", kind, algorithm.c_str(), reason);
    return false;
}

struct KEMDeleter {
    void operator()(OQS_KEM *kem) const {
        OQS_KEM_free(kem);
    }
};

struct SIGDeleter {
    void operator()(OQS_SIG *sig) const {
        OQS_SIG_free(sig);
    }
};

} /* namespace */

liboqs::liboqs(void) :
    Module("liboqs")
{
    const int kemCount = OQS_KEM_alg_count();
    for (int i = 0; i < kemCount; i++) {
        const char *name = OQS_KEM_alg_identifier(static_cast<size_t>(i));
        if ( name == nullptr ) {
            std::printf("[liboqs] skipped KEM algorithm at index %d: missing identifier\n", i);
            continue;
        }
        if ( OQS_KEM_alg_is_enabled(name) != 1 ) {
            std::printf("[liboqs] skipped KEM algorithm: %s (disabled)\n", name);
            continue;
        }

        std::unique_ptr<OQS_KEM, KEMDeleter> kem(OQS_KEM_new(name));
        if ( kem != nullptr ) {
            kemAlgorithms.emplace_back(name);
        } else {
            std::printf("[liboqs] skipped KEM algorithm: %s (OQS_KEM_new failed)\n", name);
        }
    }

    const int sigCount = OQS_SIG_alg_count();
    for (int i = 0; i < sigCount; i++) {
        const char *name = OQS_SIG_alg_identifier(static_cast<size_t>(i));
        if ( name == nullptr ) {
            std::printf("[liboqs] skipped SIG algorithm at index %d: missing identifier\n", i);
            continue;
        }
        if ( OQS_SIG_alg_is_enabled(name) != 1 ) {
            std::printf("[liboqs] skipped SIG algorithm: %s (disabled)\n", name);
            continue;
        }

        std::unique_ptr<OQS_SIG, SIGDeleter> sig(OQS_SIG_new(name));
        if ( sig != nullptr ) {
            sigAlgorithms.emplace_back(name);
        } else {
            std::printf("[liboqs] skipped SIG algorithm: %s (OQS_SIG_new failed)\n", name);
        }
    }

    std::printf("[liboqs] enabled KEM algorithms: %zu\n", kemAlgorithms.size());
    std::printf("[liboqs] enabled SIG algorithms: %zu\n", sigAlgorithms.size());
}

std::optional<bool> liboqs::OpOQSKEMSelfTest(operation::OQS_KEM_SelfTest& op) {
    if ( kemAlgorithms.empty() ) {
        return std::nullopt;
    }

    const std::string& algorithm = kemAlgorithms[static_cast<size_t>(op.selector % kemAlgorithms.size())];
    std::unique_ptr<OQS_KEM, KEMDeleter> kem(OQS_KEM_new(algorithm.c_str()));
    if ( kem == nullptr ) {
        return std::nullopt;
    }

    std::vector<uint8_t> publicKey(kem->length_public_key);
    std::vector<uint8_t> secretKey(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> sharedSecret(kem->length_shared_secret);
    std::vector<uint8_t> decapsSharedSecret(kem->length_shared_secret);
    const auto entropy = op.entropy.Get();

    SetDeterministicRandom(entropy, op.selector, "kem-keypair");
    if ( OQS_KEM_keypair(kem.get(), publicKey.data(), secretKey.data()) != OQS_SUCCESS ) {
        return Fail("KEM", algorithm, "keypair failed");
    }

    SetDeterministicRandom(entropy, op.selector, "kem-encaps");
    if ( OQS_KEM_encaps(kem.get(), ciphertext.data(), sharedSecret.data(), publicKey.data()) != OQS_SUCCESS ) {
        return Fail("KEM", algorithm, "encaps failed");
    }

    if ( OQS_KEM_decaps(kem.get(), decapsSharedSecret.data(), ciphertext.data(), secretKey.data()) != OQS_SUCCESS ) {
        return Fail("KEM", algorithm, "decaps failed");
    }

    if ( !VectorsEqual(sharedSecret, decapsSharedSecret) ) {
        return Fail("KEM", algorithm, "shared secret mismatch");
    }

    std::vector<uint8_t> mutatedCiphertext = ciphertext;
    if ( Mutate(mutatedCiphertext, op.mutation, op.selector) ) {
        std::vector<uint8_t> mutatedSharedSecret(kem->length_shared_secret);
        const OQS_STATUS status = OQS_KEM_decaps(kem.get(), mutatedSharedSecret.data(), mutatedCiphertext.data(), secretKey.data());
        if ( kem->ind_cca && status == OQS_SUCCESS && VectorsEqual(sharedSecret, mutatedSharedSecret) ) {
            return Fail("KEM", algorithm, "mutated ciphertext reproduced the original shared secret");
        }
    }

    std::vector<uint8_t> mutatedSecretKey = secretKey;
    if ( Mutate(mutatedSecretKey, op.mutation, op.selector + 1) ) {
        std::vector<uint8_t> mutatedSharedSecret(kem->length_shared_secret);
        (void)OQS_KEM_decaps(kem.get(), mutatedSharedSecret.data(), ciphertext.data(), mutatedSecretKey.data());
    }

    return true;
}

std::optional<bool> liboqs::OpOQSSIGSelfTest(operation::OQS_SIG_SelfTest& op) {
    if ( sigAlgorithms.empty() ) {
        return std::nullopt;
    }

    const std::string& algorithm = sigAlgorithms[static_cast<size_t>(op.selector % sigAlgorithms.size())];
    std::unique_ptr<OQS_SIG, SIGDeleter> sig(OQS_SIG_new(algorithm.c_str()));
    if ( sig == nullptr ) {
        return std::nullopt;
    }

    std::vector<uint8_t> publicKey(sig->length_public_key);
    std::vector<uint8_t> secretKey(sig->length_secret_key);
    std::vector<uint8_t> signature(sig->length_signature);
    const auto entropy = op.entropy.Get();
    const auto message = op.message.Get();
    size_t signatureLen = 0;

    SetDeterministicRandom(entropy, op.selector, "sig-keypair");
    if ( OQS_SIG_keypair(sig.get(), publicKey.data(), secretKey.data()) != OQS_SUCCESS ) {
        return Fail("SIG", algorithm, "keypair failed");
    }

    SetDeterministicRandom(entropy, op.selector, "sig-sign");
    if ( OQS_SIG_sign(sig.get(), signature.data(), &signatureLen, message.data(), message.size(), secretKey.data()) != OQS_SUCCESS ) {
        return Fail("SIG", algorithm, "sign failed");
    }

    if ( signatureLen > signature.size() ) {
        return Fail("SIG", algorithm, "signature length exceeds maximum");
    }

    if ( OQS_SIG_verify(sig.get(), message.data(), message.size(), signature.data(), signatureLen, publicKey.data()) != OQS_SUCCESS ) {
        return Fail("SIG", algorithm, "verify failed for generated signature");
    }

    std::vector<uint8_t> mutatedMessage = message;
    if ( Mutate(mutatedMessage, op.mutation, op.selector) ) {
        if ( OQS_SIG_verify(sig.get(), mutatedMessage.data(), mutatedMessage.size(), signature.data(), signatureLen, publicKey.data()) == OQS_SUCCESS ) {
            return Fail("SIG", algorithm, "mutated message verified");
        }
    }

    std::vector<uint8_t> mutatedSignature = signature;
    mutatedSignature.resize(signatureLen);
    if ( Mutate(mutatedSignature, op.mutation, op.selector + 1) ) {
        if ( OQS_SIG_verify(sig.get(), message.data(), message.size(), mutatedSignature.data(), mutatedSignature.size(), publicKey.data()) == OQS_SUCCESS ) {
            return Fail("SIG", algorithm, "mutated signature verified");
        }
    }

    std::vector<uint8_t> mutatedPublicKey = publicKey;
    if ( Mutate(mutatedPublicKey, op.mutation, op.selector + 2) ) {
        if ( OQS_SIG_verify(sig.get(), message.data(), message.size(), signature.data(), signatureLen, mutatedPublicKey.data()) == OQS_SUCCESS ) {
            return Fail("SIG", algorithm, "mutated public key verified");
        }
    }

    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
