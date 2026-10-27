#pragma once
#include "../includes.h"
#include "../includes/tpm20.h"

namespace svm {

typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
class tpm_crypto {
  public:
    static tpm_crypto* get();
    NTSTATUS generate_random(u8* buffer, u32 size);
    NTSTATUS hash_sha256(const u8* input, u32 input_size, u8* output);
    NTSTATUS hash_generic(LPCWSTR algorithm, const u8* input, u32 input_size, u8* output, u32 output_size);
    NTSTATUS extend_pcr(u8* pcr_value, const u8* new_data);
    NTSTATUS extend_pcr_alg(u16 alg_id, u8* pcr_value, const u8* new_digest, u32 digest_size);
    NTSTATUS generate_ek_key();
    NTSTATUS export_ek_public(u8* buffer, u32* buffer_size);
    NTSTATUS sign_with_ek(const u8* hash, u32 hash_size, u8* sig, u32* sig_size);
    NTSTATUS verify_with_ek(const u8* hash, u32 hash_size, const u8* sig, u32 sig_size);
    // NGC-grade object support: real RSA-2048 keys for guest-created TPM
    // objects (Hello PIN keys), so signatures verify and PINs work.
    NTSTATUS rsa_generate_2048(u8* modulus256, u8* prime1_128, u8* prime2_128, u8* exponent, u32* exponent_len);
    NTSTATUS rsa_sign_pkcs1(const u8* modulus256, const u8* prime1_128, const u8* prime2_128,
        const u8* exponent, u32 exponent_len, const u8* digest32, u8* sig256);
    svm::svmroot_error_t get_tpm_key(svm::pvcpu_t vcpu, u64 buffer_gva);
    NTSTATUS hash_data(u8* input, u32 input_size, u8* output, u32 output_size) {
        return (output_size >= 32) ? hash_sha256(input, input_size, output) : STATUS_BUFFER_TOO_SMALL;
    }

  private:
    tpm_crypto() = default;
    tpm_crypto(const tpm_crypto&) = delete;
    tpm_crypto& operator=(const tpm_crypto&) = delete;
    NTSTATUS initialize();
    NTSTATUS init_provider(BCRYPT_ALG_HANDLE* handle, LPCWSTR algorithm);
    void cleanup();
    struct {
        BCRYPT_ALG_HANDLE sha256 = nullptr;
        BCRYPT_ALG_HANDLE rng = nullptr;
        BCRYPT_ALG_HANDLE rsa = nullptr;
        BCRYPT_KEY_HANDLE ek_key = nullptr;
    } handles_;
    bool initialized_ = false;
};
}
