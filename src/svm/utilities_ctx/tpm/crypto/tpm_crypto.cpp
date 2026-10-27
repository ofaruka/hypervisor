#include "tpm_crypto.hpp"
#include <bcrypt.h>

namespace svm {

tpm_crypto* tpm_crypto::get() {
    static tpm_crypto instance;

    if (!instance.initialized_) {
        if (!NT_SUCCESS(instance.initialize()))
            return nullptr;
        instance.initialized_ = true;
    }

    return &instance;
}

NTSTATUS tpm_crypto::init_provider(BCRYPT_ALG_HANDLE* handle, LPCWSTR algorithm) {
    return BCryptOpenAlgorithmProvider(handle, algorithm, nullptr, BCRYPT_PROV_DISPATCH);
}

NTSTATUS tpm_crypto::initialize() {
    NTSTATUS status;
    status = init_provider(&handles_.sha256, BCRYPT_SHA256_ALGORITHM);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = init_provider(&handles_.rng, BCRYPT_RNG_ALGORITHM);

    if (!NT_SUCCESS(status)) {
        cleanup();
        return status;
    }

    status = init_provider(&handles_.rsa, BCRYPT_RSA_ALGORITHM);

    if (!NT_SUCCESS(status)) {
        cleanup();
        return status;
    }

    status = generate_ek_key();

    if (!NT_SUCCESS(status)) {
        cleanup();
        return status;
    }

    return STATUS_SUCCESS;
}

void tpm_crypto::cleanup() {
    if (handles_.ek_key) {
        BCryptDestroyKey(handles_.ek_key);
        handles_.ek_key = nullptr;
    }

    if (handles_.rsa) {
        BCryptCloseAlgorithmProvider(handles_.rsa, 0);
        handles_.rsa = nullptr;
    }

    if (handles_.rng) {
        BCryptCloseAlgorithmProvider(handles_.rng, 0);
        handles_.rng = nullptr;
    }

    if (handles_.sha256) {
        BCryptCloseAlgorithmProvider(handles_.sha256, 0);
        handles_.sha256 = nullptr;
    }
}

NTSTATUS tpm_crypto::generate_random(u8* buffer, u32 size) {
    if (!handles_.rng) {
        return STATUS_INVALID_HANDLE;
    }

    return BCryptGenRandom(handles_.rng, buffer, size, 0);
}

NTSTATUS tpm_crypto::hash_sha256(const u8* input, u32 input_size, u8* output) {
    if (!handles_.sha256) {
        return STATUS_INVALID_HANDLE;
    }

    ULONG obj_size = 0, data_size = 0;
    NTSTATUS status =
        BCryptGetProperty(handles_.sha256, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_size, sizeof(obj_size), &data_size, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    u8* hash_obj = (u8*)memory::get()->alloc_nonpaged_pool(obj_size);

    if (!hash_obj) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(handles_.sha256, &hash, hash_obj, obj_size, nullptr, 0, 0);

    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hash, (PUCHAR)input, input_size, 0);

        if (NT_SUCCESS(status))
            status = BCryptFinishHash(hash, output, 32, 0);
    }

    if (hash) {
        BCryptDestroyHash(hash);
    }

    ExFreePool(hash_obj);
    return status;
}

NTSTATUS tpm_crypto::hash_generic(LPCWSTR algorithm, const u8* input, u32 input_size, u8* output, u32 output_size) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, algorithm, nullptr, BCRYPT_PROV_DISPATCH);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG obj_size = 0, data_size = 0;
    status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_size, sizeof(obj_size), &data_size, 0);

    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return status;
    }

    u8* hash_obj = (u8*)memory::get()->alloc_nonpaged_pool(obj_size);

    if (!hash_obj) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(alg, &hash, hash_obj, obj_size, nullptr, 0, 0);

    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hash, (PUCHAR)input, input_size, 0);

        if (NT_SUCCESS(status))
            status = BCryptFinishHash(hash, output, output_size, 0);
    }

    if (hash) {
        BCryptDestroyHash(hash);
    }

    ExFreePool(hash_obj);
    BCryptCloseAlgorithmProvider(alg, 0);
    return status;
}

NTSTATUS tpm_crypto::extend_pcr(u8* pcr_value, const u8* new_data) {
    u8 concat[64];
    RtlCopyMemory(concat, pcr_value, 32);
    RtlCopyMemory(concat + 32, new_data, 32);
    return hash_sha256(concat, sizeof(concat), pcr_value);
}

NTSTATUS tpm_crypto::extend_pcr_alg(u16 alg_id, u8* pcr_value, const u8* new_digest, u32 digest_size) {
    LPCWSTR alg_name;

    switch (alg_id) {
    case 0x0004:
        alg_name = BCRYPT_SHA1_ALGORITHM;
        break;
    case 0x000B:
        alg_name = BCRYPT_SHA256_ALGORITHM;
        break;
    case 0x000C:
        alg_name = BCRYPT_SHA384_ALGORITHM;
        break;
    case 0x000D:
        alg_name = BCRYPT_SHA512_ALGORITHM;
        break;
    default:
        return STATUS_NOT_SUPPORTED;
    }

    u8 concat[128];
    RtlCopyMemory(concat, pcr_value, digest_size);
    RtlCopyMemory(concat + digest_size, new_digest, digest_size);
    return hash_generic(alg_name, concat, digest_size * 2, pcr_value, digest_size);
}

NTSTATUS tpm_crypto::generate_ek_key() {
    if (!handles_.rsa) {
        return STATUS_INVALID_HANDLE;
    }

    if (handles_.ek_key) {
        BCryptDestroyKey(handles_.ek_key);
        handles_.ek_key = nullptr;
    }

    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS status = BCryptGenerateKeyPair(handles_.rsa, &key, 2048, 0);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptFinalizeKeyPair(key, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(key);
        return status;
    }

    handles_.ek_key = key;
    return STATUS_SUCCESS;
}

NTSTATUS tpm_crypto::export_ek_public(u8* buffer, u32* buffer_size) {
    if (!handles_.ek_key) {
        return STATUS_INVALID_HANDLE;
    }

    ULONG size = *buffer_size;
    NTSTATUS status = BCryptExportKey(handles_.ek_key, nullptr, BCRYPT_RSAPUBLIC_BLOB, buffer, size, &size, 0);
    *buffer_size = size;
    return status;
}

NTSTATUS tpm_crypto::sign_with_ek(const u8* hash, u32 hash_size, u8* sig, u32* sig_size) {
    if (!handles_.ek_key) {
        return STATUS_INVALID_HANDLE;
    }

    BCRYPT_PKCS1_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM};
    ULONG size = *sig_size;
    NTSTATUS status =
        BCryptSignHash(handles_.ek_key, &padding, (PUCHAR)hash, hash_size, sig, size, &size, BCRYPT_PAD_PKCS1);
    *sig_size = size;
    return status;
}

NTSTATUS tpm_crypto::rsa_generate_2048(u8* modulus256, u8* prime1_128, u8* prime2_128, u8* exponent, u32* exponent_len) {
    if (!handles_.rsa) {
        return STATUS_INVALID_HANDLE;
    }

    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS status = BCryptGenerateKeyPair(handles_.rsa, &key, 2048, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptFinalizeKeyPair(key, 0);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG size = 0;
    status = BCryptExportKey(key, nullptr, BCRYPT_RSAPRIVATE_BLOB, nullptr, 0, &size, 0);
    u8* blob = nullptr;
    if (status == STATUS_BUFFER_TOO_SMALL) {
        blob = static_cast<u8*>(memory::get()->alloc_nonpaged_pool(size));
        if (blob) {
            status = BCryptExportKey(key, nullptr, BCRYPT_RSAPRIVATE_BLOB, blob, size, &size, 0);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (NT_SUCCESS(status)) {
        auto* hdr = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob);
        if (hdr->cbModulus == 256 && hdr->cbPrime1 == 128 && hdr->cbPrime2 == 128 &&
            hdr->cbPublicExp > 0 && hdr->cbPublicExp <= 4) {
            u8* ptr = blob + sizeof(BCRYPT_RSAKEY_BLOB);
            RtlCopyMemory(exponent, ptr, hdr->cbPublicExp);
            *exponent_len = hdr->cbPublicExp;
            ptr += hdr->cbPublicExp;
            RtlCopyMemory(modulus256, ptr, 256);
            ptr += 256;
            RtlCopyMemory(prime1_128, ptr, 128);
            ptr += 128;
            RtlCopyMemory(prime2_128, ptr, 128);
        } else {
            status = STATUS_UNSUCCESSFUL;
        }
    }

    if (blob) {
        memory::get()->free_nonpaged_pool(blob);
    }
    BCryptDestroyKey(key);
    return status;
}

NTSTATUS tpm_crypto::rsa_sign_pkcs1(const u8* modulus256, const u8* prime1_128, const u8* prime2_128,
    const u8* exponent, u32 exponent_len, const u8* digest32, u8* sig256) {
    if (!handles_.rsa) {
        return STATUS_INVALID_HANDLE;
    }

    if (exponent_len == 0 || exponent_len > 4) {
        return STATUS_INVALID_PARAMETER;
    }

    const ULONG blob_size = sizeof(BCRYPT_RSAKEY_BLOB) + exponent_len + 256 + 128 + 128;
    u8 blob[sizeof(BCRYPT_RSAKEY_BLOB) + 4 + 256 + 128 + 128];

    auto* hdr = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob);
    hdr->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    hdr->BitLength = 2048;
    hdr->cbPublicExp = exponent_len;
    hdr->cbModulus = 256;
    hdr->cbPrime1 = 128;
    hdr->cbPrime2 = 128;

    u8* ptr = blob + sizeof(BCRYPT_RSAKEY_BLOB);
    RtlCopyMemory(ptr, exponent, exponent_len);
    ptr += exponent_len;
    RtlCopyMemory(ptr, modulus256, 256);
    ptr += 256;
    RtlCopyMemory(ptr, prime1_128, 128);
    ptr += 128;
    RtlCopyMemory(ptr, prime2_128, 128);

    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS status = BCryptImportKeyPair(handles_.rsa, nullptr, BCRYPT_RSAPRIVATE_BLOB, &key, blob, blob_size, 0);
    if (NT_SUCCESS(status)) {
        BCRYPT_PKCS1_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM};
        ULONG out_size = 256;
        status = BCryptSignHash(key, &padding, (PUCHAR)digest32, 32, sig256, 256, &out_size, BCRYPT_PAD_PKCS1);
        BCryptDestroyKey(key);
    }

    RtlSecureZeroMemory(blob, sizeof(blob));
    return status;
}

NTSTATUS tpm_crypto::verify_with_ek(const u8* hash, u32 hash_size, const u8* sig, u32 sig_size) {
    if (!handles_.ek_key) {
        return STATUS_INVALID_HANDLE;
    }

    BCRYPT_PKCS1_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM};
    return BCryptVerifySignature(handles_.ek_key, &padding, (PUCHAR)hash, hash_size, (PUCHAR)sig, sig_size,
                                 BCRYPT_PAD_PKCS1);
}

svm::svmroot_error_t tpm_crypto::get_tpm_key(svm::pvcpu_t vcpu, u64 buffer_gva) {
    if (!buffer_gva) {
        return svm::svmroot_error_t::error_failed;
    }

    u32 key_size = tpm::get()->get_ek_public_size();

    if (key_size == 0 || key_size > sizeof(TPM2B_PUBLIC_KEY_RSA_TRANSFER::buffer))
        return svm::svmroot_error_t::error_failed;
    TPM2B_PUBLIC_KEY_RSA_TRANSFER transfer = {};
    transfer.size = (u16)key_size;
    RtlCopyMemory(transfer.buffer, tpm::get()->get_ek_public(), key_size);
    auto result = memory_access::get()->read_virtual_memory(
        vcpu,
        vcpu->host_vmcb.state_save_area.cr3,
        buffer_gva,
        reinterpret_cast<u64>(&transfer),
        sizeof(transfer));
    return (result == svm::svmroot_error_t::error_success) ? svm::svmroot_error_t::error_success
                                                           : svm::svmroot_error_t::error_failed;
}
}
