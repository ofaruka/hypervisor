#include "tpm.hpp"
#include <bcrypt.h>

namespace svm {

constexpr u8 tpm::EK_AUTH_POLICY[32];

tpm* tpm::get() {
    static tpm instance;
    static bool initialized = false;

    if (!initialized) {
        instance.initialize();
        initialized = true;
    }

    return &instance;
}

void tpm::initialize() {
    KeInitializeSpinLock(&lock_);
    RtlZeroMemory(&state_, sizeof(state_));
    state_.regs.access = 0xA1;
    state_.regs.sts = TIS_PC_VALID | TIS_PC_STS_EXPECT;
    state_.regs.interface_id = 0x00082100;
    state_.regs.interface_capability = 0x30000697;
    state_.regs.did_vid = 0x1022;
    state_.regs.rid = 0x4E;
    state_.regs.burst_count = 4096;
    state_.locality = 0xFF;
    state_.pcr_counter = 1;
    state_.ek_cert_generated = false;
    state_.ek_cert_der_size = 0;
    seed_identity();
    initialize_pcrs();

    if (NT_SUCCESS(tpm_crypto::get()->generate_ek_key())) {
        state_.ek_pub_size = 0;
        tpm_crypto::get()->export_ek_public(nullptr, &state_.ek_pub_size);

        if (state_.ek_pub_size > 0 && state_.ek_pub_size <= sizeof(state_.ek_pub))
            tpm_crypto::get()->export_ek_public(state_.ek_pub, &state_.ek_pub_size);
    }

    // Deterministic EK/SRK modulus derived from the identity seed (see
    // derive_ek_public); re-derived when the driver pushes the profile seed.
    derive_ek_public();

    if (auto* nv = create_nv_index(0x01C00002, 0x62060001, 0)) {
        (void)nv;
    }

    debug::log_info("TPM MMIO handler initialized (synchronized with vTPM driver)\n");
}

bool tpm::is_tpm_address(u64 pa) {
    return pa >= 0xFED40000 && pa <= 0xFED44FFF;
}

void tpm::initialize_pcrs() {
    RtlZeroMemory(state_.pcr_sha1, sizeof(state_.pcr_sha1));
    RtlZeroMemory(state_.pcr_sha256, sizeof(state_.pcr_sha256));
    RtlZeroMemory(state_.pcr_sha384, sizeof(state_.pcr_sha384));
    RtlZeroMemory(state_.pcr_sha512, sizeof(state_.pcr_sha512));
    state_.supported_banks = 0x02;
    static const u8 pcr0[32] = {0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f,
                                0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f,
                                0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69};
    RtlCopyMemory(state_.pcr_sha256[0], pcr0, 32);
    static const u8 pcr1[32] = {0x3d, 0x67, 0xf7, 0x2f, 0x87, 0x6c, 0xb4, 0xc5, 0x12, 0xf3, 0x44,
                                0xb8, 0x7e, 0xfa, 0x1d, 0x93, 0x12, 0x76, 0xaf, 0xba, 0xe4, 0x64,
                                0xfa, 0x07, 0x8d, 0x37, 0x84, 0xa7, 0xc7, 0x5c, 0xc5, 0xf6};
    RtlCopyMemory(state_.pcr_sha256[1], pcr1, 32);
    static const u8 pcr2[32] = {0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f,
                                0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f,
                                0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69};
    RtlCopyMemory(state_.pcr_sha256[2], pcr2, 32);
    static const u8 pcr3[32] = {0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 0x1f, 0x44, 0x3f,
                                0x15, 0x62, 0xbe, 0xec, 0x8d, 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f,
                                0xcf, 0x9a, 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69};
    RtlCopyMemory(state_.pcr_sha256[3], pcr3, 32);
    static const u8 pcr4[32] = {0xa5, 0x36, 0xde, 0x04, 0xb6, 0xfc, 0x2e, 0x56, 0x05, 0x89, 0xa1,
                                0xfb, 0x05, 0xfe, 0x77, 0xfa, 0x8c, 0xb0, 0xab, 0x37, 0x2a, 0xdb,
                                0x5e, 0x1b, 0x0a, 0x30, 0x27, 0x3d, 0x6a, 0x13, 0x82, 0xf8};
    RtlCopyMemory(state_.pcr_sha256[4], pcr4, 32);
    static const u8 pcr5[32] = {0x72, 0x13, 0xfe, 0x6e, 0x3b, 0xa6, 0xb9, 0x6c, 0x8f, 0x23, 0xef,
                                0x40, 0xab, 0x88, 0xc2, 0x6e, 0xa7, 0x16, 0xe1, 0x45, 0x0b, 0xfa,
                                0x9a, 0x0e, 0xd9, 0x4b, 0x7e, 0x08, 0xcc, 0x50, 0x70, 0x46};
    RtlCopyMemory(state_.pcr_sha256[5], pcr5, 32);
    static const u8 pcr7[32] = {0xe0, 0xa7, 0xc0, 0xaf, 0x38, 0x8d, 0x8b, 0xb9, 0xd2, 0x65, 0x9f,
                                0x59, 0x90, 0x6f, 0x5f, 0xe3, 0xca, 0xde, 0x56, 0x75, 0x17, 0x73,
                                0xc2, 0x25, 0xad, 0xf5, 0x5f, 0x36, 0xdd, 0xb9, 0xa1, 0x67};
    RtlCopyMemory(state_.pcr_sha256[7], pcr7, 32);
    static const u8 pcr11[32] = {0x0f, 0xe6, 0xe8, 0xf2, 0x11, 0x0d, 0x5d, 0x53, 0x93, 0x5c, 0x9e,
                                 0x7d, 0x6f, 0x6b, 0xf7, 0x22, 0x59, 0x8b, 0x55, 0x05, 0x95, 0xaa,
                                 0xbd, 0xc6, 0xe4, 0xfd, 0x2e, 0xcd, 0xf3, 0x10, 0xf9, 0x80};
    RtlCopyMemory(state_.pcr_sha256[11], pcr11, 32);
    static const u8 pcr12[32] = {0x86, 0xa9, 0x19, 0x3f, 0x3c, 0xb5, 0x85, 0x09, 0xb7, 0xb8, 0x71,
                                 0x94, 0xa5, 0x59, 0x55, 0x5c, 0xc7, 0x4f, 0x56, 0xc7, 0x6b, 0x3f,
                                 0xc0, 0x7c, 0xc5, 0x12, 0x19, 0xe9, 0x43, 0x24, 0xf1, 0x65};
    RtlCopyMemory(state_.pcr_sha256[12], pcr12, 32);
    static const u8 pcr13[32] = {0xfb, 0xa3, 0xa0, 0xd6, 0x32, 0x85, 0xca, 0xea, 0xd0, 0x0b, 0x40,
                                 0xf2, 0x24, 0x22, 0x3b, 0xb6, 0xc2, 0x26, 0x43, 0x8b, 0xb7, 0xcf,
                                 0x5d, 0x80, 0x35, 0x81, 0x5a, 0x9c, 0x01, 0x56, 0x6d, 0x5f};
    RtlCopyMemory(state_.pcr_sha256[13], pcr13, 32);
    static const u8 pcr14[32] = {0xbf, 0xde, 0x51, 0x3a, 0x54, 0xa0, 0xe6, 0xe9, 0x82, 0x67, 0x94,
                                 0x23, 0xad, 0xa3, 0x14, 0x19, 0xf9, 0x85, 0x6f, 0x7d, 0x53, 0x4e,
                                 0x42, 0xd9, 0x85, 0xf8, 0x59, 0x91, 0x50, 0x05, 0x51, 0x6f};
    RtlCopyMemory(state_.pcr_sha256[14], pcr14, 32);

    for (int i = 17; i <= 22; i++) {
        RtlFillMemory(state_.pcr_sha1[i], 20, 0xFF);
        RtlFillMemory(state_.pcr_sha256[i], 32, 0xFF);
        RtlFillMemory(state_.pcr_sha384[i], 48, 0xFF);
        RtlFillMemory(state_.pcr_sha512[i], 64, 0xFF);
    }

    state_.pcr_counter = 1;
}

void tpm::set_pcr_values(const pcr_all_banks& banks) {
    KIRQL old_irql;
    KeAcquireSpinLock(&lock_, &old_irql);
    RtlCopyMemory(state_.pcr_sha1, banks.sha1, sizeof(state_.pcr_sha1));
    RtlCopyMemory(state_.pcr_sha256, banks.sha256, sizeof(state_.pcr_sha256));
    RtlCopyMemory(state_.pcr_sha384, banks.sha384, sizeof(state_.pcr_sha384));
    RtlCopyMemory(state_.pcr_sha512, banks.sha512, sizeof(state_.pcr_sha512));

    if (banks.supported_banks != 0)
        state_.supported_banks = banks.supported_banks;
    state_.pcr_counter++;
    KeReleaseSpinLock(&lock_, old_irql);
    debug::log_info("PCR values updated from driver sync (supported_banks=0x%X)\n", state_.supported_banks);
}

u32 tpm::big_endian_to_little_endian32(u32 v) {
    return ((v >> 24) & 0xFF) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) | ((v << 24) & 0xFF000000);
}

u16 tpm::big_endian_to_little_endian16(u16 v) {
    return (u16)(((v >> 8) & 0xFF) | ((v << 8) & 0xFF00));
}

u8 tpm::lcg_byte(u64& seed) {
    seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
    return (u8)(seed >> 33);
}

void tpm::lcg_fill(u64& seed, u8* buf, u32 len) {
    for (u32 i = 0; i < len; i++)
        buf[i] = lcg_byte(seed);
}

void tpm::write_response_header(u8* buf, u16 tag, u32 size, u32 rc) {
    auto* hdr = reinterpret_cast<TPM2_RESPONSE_HEADER*>(buf);
    hdr->tag = big_endian_to_little_endian16(tag);
    hdr->paramSize = big_endian_to_little_endian32(size);
    hdr->responseCode = big_endian_to_little_endian32(rc);
}

void tpm::send_error(TPM_RC code) {
    write_response_header(state_.regs.data_fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), code);
    state_.regs.response_size = sizeof(TPM2_RESPONSE_HEADER);
    state_.fifo_index = 0;
    state_.regs.sts |= TIS_PC_STS_DATA;
}

void tpm::send_response(u32 size) {
    state_.regs.response_size = size;
    state_.fifo_index = 0;
    state_.regs.sts |= TIS_PC_STS_DATA;
    state_.regs.sts &= ~TPM_STS_EXPECT;
}

u32 tpm::write_auth_session_response(u8* ptr) {
    u8* start = ptr;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(32);
    ptr += 2;
    LARGE_INTEGER perf;
    KeQueryPerformanceCounter(&perf);
    u64 seed = perf.QuadPart ^ 0xB0B1B2B3B4B5B6B7ULL;
    lcg_fill(seed, ptr, 32);
    ptr += 32;
    *ptr = 0x01;
    ptr += 1;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0);
    ptr += 2;
    return (u32)(ptr - start);
}

void tpm::copy_rsa_modulus(u8* dest, u16 max_size) {
    if (state_.ek_pub_size > sizeof(BCRYPT_RSAKEY_BLOB)) {
        auto* rsa = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(state_.ek_pub);
        u8* mod = state_.ek_pub + sizeof(BCRYPT_RSAKEY_BLOB) + rsa->cbPublicExp;
        RtlCopyMemory(dest, mod, min((u32)max_size, rsa->cbModulus));
    } else if (state_.ek_pub_size > 0) {
        RtlCopyMemory(dest, state_.ek_pub, min((u16)state_.ek_pub_size, max_size));
    }
}

u8* tpm::write_ek_rsa_public(u8* ptr) {
    constexpr u16 KEY_SIZE = 256;
    constexpr u16 TPMT = 2 + 2 + 4 + 2 + 32 + 2 + 2 + 2 + 2 + 2 + 4 + 2 + KEY_SIZE;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(TPMT);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x0001);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x000B);
    ptr += 2;
    *reinterpret_cast<u32*>(ptr) = big_endian_to_little_endian32(0x000300F2);
    ptr += 4;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(32);
    ptr += 2;
    RtlCopyMemory(ptr, EK_AUTH_POLICY, 32);
    ptr += 32;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x0006);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(128);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x0043);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x0010);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(2048);
    ptr += 2;
    *reinterpret_cast<u32*>(ptr) = big_endian_to_little_endian32(0);
    ptr += 4;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(KEY_SIZE);
    ptr += 2;
    RtlZeroMemory(ptr, KEY_SIZE);
    copy_rsa_modulus(ptr, KEY_SIZE);
    ptr += KEY_SIZE;
    return ptr;
}

u8* tpm::write_srk_rsa_public(u8* ptr) {
    constexpr u16 KEY_SIZE = 256;
    constexpr u16 TPMT = 2 + 2 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 2 + KEY_SIZE;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(TPMT);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x0001);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x000B);
    ptr += 2;
    *reinterpret_cast<u32*>(ptr) = big_endian_to_little_endian32(0x00030472);
    ptr += 4;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x0006);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(128);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x0043);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(0x0010);
    ptr += 2;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(2048);
    ptr += 2;
    *reinterpret_cast<u32*>(ptr) = big_endian_to_little_endian32(0);
    ptr += 4;
    *reinterpret_cast<u16*>(ptr) = big_endian_to_little_endian16(KEY_SIZE);
    ptr += 2;
    RtlZeroMemory(ptr, KEY_SIZE);
    copy_rsa_modulus(ptr, KEY_SIZE);

    for (int i = 0; i < 8 && i < KEY_SIZE; i++)
        ptr[i] ^= 0x53;
    ptr += KEY_SIZE;
    return ptr;
}

tpm::nv_entry_t* tpm::find_nv_index(u32 index) {
    for (u32 i = 0; i < state_.nv_count; i++)
        if (state_.nv[i].defined && state_.nv[i].index == index) {
            return &state_.nv[i];
        }

    return nullptr;
}

tpm::nv_entry_t* tpm::create_nv_index(u32 index, u32 attributes, u32 size) {
    if (state_.nv_count >= MAX_NV_INDICES) {
        return nullptr;
    }

    auto* nv = &state_.nv[state_.nv_count++];
    nv->defined = true;
    nv->index = index;
    nv->attributes = attributes;
    nv->size = size;
    RtlZeroMemory(nv->data, MAX_NV_SIZE);
    return nv;
}

void tpm::seed_identity() {
    // Deterministic fallback so the emulator is never left uninitialized. The
    // guest driver pushes the real profile seed over the set_tpm_seed vmmcall
    // during its TPM init (before vgk.sys queries TPM state);
    // set_identity_seed() then overrides this value and re-derives everything
    // that depends on it.
    state_.id_seed = 0x9C27B4D15EA5EED5ULL;
    debug::log_info("vTPM: identity seed loaded (fallback)\n");
}

void tpm::derive_ek_public() {
    // The EK/SRK public identity must be stable across boots: anything sealed
    // to this TPM (Windows Hello PIN / NGC containers) breaks the moment the
    // endorsement identity changes. Present a deterministic modulus derived
    // from the persistent identity seed rather than the per-boot BCrypt
    // keypair (kept for sign_with_ek users only). Layout matches the
    // BCRYPT_RSAKEY_BLOB export that copy_rsa_modulus() expects.
    // Callers: initialize() (unlocked, single-threaded) and set_identity_seed()
    // (under lock_).
    u8 blob[24 + 3 + 256];
    u32* h = reinterpret_cast<u32*>(blob);
    h[0] = 0x31415352; // BCRYPT_RSAPUBLIC_MAGIC ("RSA1")
    h[1] = 2048;
    h[2] = 3;          // cbPublicExp
    h[3] = 256;        // cbModulus
    h[4] = 0;
    h[5] = 0;
    blob[24] = 0x01;
    blob[25] = 0x00;
    blob[26] = 0x01;
    u64 s = state_.id_seed ^ 0x454B4D4F44554C53ULL;
    lcg_fill(s, blob + 27, 256);
    blob[27] |= 0x80;        // exactly 2048 bits, like a real modulus
    blob[27 + 255] |= 0x01;  // odd
    RtlCopyMemory(state_.ek_pub, blob, sizeof(blob));
    state_.ek_pub_size = sizeof(blob);
}

void tpm::set_identity_seed(u64 seed) {
    // Called from the set_tpm_seed vmmcall when the driver pushes the profile
    // seed during its TPM init, before vgk.sys queries TPM state. PCRs are not
    // derived from the seed and are pushed separately via set_tpm_pcrs, so they
    // are left untouched here.
    KIRQL old_irql;
    KeAcquireSpinLock(&lock_, &old_irql);

    state_.id_seed = seed;

    // Re-derive/reset everything the seed feeds so no material derived from
    // the fallback identity survives:
    //  - the deterministic EK/SRK modulus
    derive_ek_public();
    //  - the lazily-generated EK certificate state
    state_.ek_cert_generated = false;
    state_.ek_cert_der_size = 0;
    if (auto* nv = find_nv_index(0x01C00002)) {
        nv->size = 0;
        RtlZeroMemory(nv->data, MAX_NV_SIZE);
    }
    //  - guest-created objects, which are only valid under the identity that
    //    produced them
    for (u32 i = 0; i < ARRAYSIZE(state_.objects); i++) {
        if (state_.objects[i].used) {
            RtlSecureZeroMemory(&state_.objects[i], sizeof(state_.objects[i]));
        }
    }

    KeReleaseSpinLock(&lock_, old_irql);
    debug::log_info("vTPM: identity seed updated from driver push\n");
}

void tpm::compute_name(const u8* public_area, u32 public_size, u8* out34) {
    // TPM Name = nameAlg(SHA256) || SHA256(marshaled TPMT_PUBLIC)
    out34[0] = 0x00;
    out34[1] = 0x0B;

    auto* crypto = tpm_crypto::get();
    if (crypto && NT_SUCCESS(crypto->hash_sha256(public_area, public_size, out34 + 2)))
        return;

    // Deterministic fallback if the crypto provider is unavailable
    u64 s = state_.id_seed ^ 0x4E414D4548415348ULL;
    for (u32 i = 0; i < public_size; i++) {
        s ^= public_area[i];
        s *= 0x100000001B3ULL;
    }
    lcg_fill(s, out34 + 2, 32);
}

u8* tpm::write_computed_name(u8* ptr, const u8* public_area, u32 public_size) {
    // Writes nameAlg || digest (34 bytes); callers emit the TPM2B_NAME size
    compute_name(public_area, public_size, ptr);
    return ptr + 34;
}

u8* tpm::params_after_auth(u8* cmd, u32 handles_size, bool has_sessions) {
    u8* p = cmd + sizeof(TPM2_COMMAND_HEADER) + handles_size;
    if (has_sessions) {
        u32 auth_size = big_endian_to_little_endian32(*reinterpret_cast<u32*>(p));
        p += 4 + auth_size;
    }
    return p;
}

bool tpm::read_pw_auth(u8* cmd, u32 handles_size, bool has_sessions, u8* auth, u16* auth_len) {
    *auth_len = 0;
    if (!has_sessions)
        return false;

    u8* s = cmd + sizeof(TPM2_COMMAND_HEADER) + handles_size + 4; // skip authorizationSize
    u32 session_handle = big_endian_to_little_endian32(*reinterpret_cast<u32*>(s));
    s += 4;
    u16 nonce_len = big_endian_to_little_endian16(*reinterpret_cast<u16*>(s));
    s += 2 + nonce_len;
    s += 1; // sessionAttributes
    u16 len = big_endian_to_little_endian16(*reinterpret_cast<u16*>(s));
    s += 2;

    if (session_handle != TPM_RS_PW || len > 64)
        return false;

    RtlCopyMemory(auth, s, len);
    *auth_len = len;
    return true;
}

bool tpm::auth_matches(const object_slot_t* slot, u8* cmd, u32 handles_size, bool has_sessions) {
    if (slot->auth_len == 0)
        return true;

    u8 auth[64];
    u16 auth_len = 0;
    if (!read_pw_auth(cmd, handles_size, has_sessions, auth, &auth_len))
        return true; // policy/HMAC sessions are not verified by the emulator

    if (auth_len != slot->auth_len)
        return false;
    return RtlCompareMemory(auth, slot->auth, auth_len) == auth_len;
}

tpm::object_slot_t* tpm::alloc_slot(u32* handle_out) {
    for (u32 i = 0; i < ARRAYSIZE(state_.objects); i++) {
        if (!state_.objects[i].used) {
            RtlZeroMemory(&state_.objects[i], sizeof(state_.objects[i]));
            state_.objects[i].used = true;
            state_.objects[i].handle = 0x80000010 + i;
            *handle_out = state_.objects[i].handle;
            return &state_.objects[i];
        }
    }
    return nullptr;
}

tpm::object_slot_t* tpm::find_slot(u32 handle) {
    for (u32 i = 0; i < ARRAYSIZE(state_.objects); i++) {
        if (state_.objects[i].used && state_.objects[i].handle == handle)
            return &state_.objects[i];
    }
    return nullptr;
}

void tpm::free_slot(u32 handle) {
    object_slot_t* slot = find_slot(handle);
    if (slot) {
        RtlSecureZeroMemory(slot, sizeof(*slot));
        slot->used = false;
    }
}

u16 tpm::marshal_blob(const object_slot_t* slot, u8* out) {
    // Our own opaque private-blob format; the guest only stores it and hands
    // it back to Load, so the object effectively persists inside the caller's
    // storage (e.g. the NGC container on disk).
    u8* p = out;
    *p++ = 'C';
    *p++ = 'B';
    *p++ = 'T';
    *p++ = '1';
    *reinterpret_cast<u16*>(p) = slot->public_size;
    p += 2;
    RtlCopyMemory(p, slot->public_area, slot->public_size);
    p += slot->public_size;
    *reinterpret_cast<u16*>(p) = slot->auth_len;
    p += 2;
    RtlCopyMemory(p, slot->auth, slot->auth_len);
    p += slot->auth_len;
    *reinterpret_cast<u16*>(p) = slot->priv_len;
    p += 2;
    RtlCopyMemory(p, slot->priv, slot->priv_len);
    p += slot->priv_len;
    *p++ = slot->is_rsa ? 1 : 0;
    return static_cast<u16>(p - out);
}

u64 tpm::handle_read(u64 pa, u32 offset, u32 size) {
    KIRQL irql;
    KeAcquireSpinLock(&lock_, &irql);
    state_.locality = (pa >> 12) & 0x7;
    offset &= 0xFFF;

    if (size != 1 && size != 2 && size != 4 && size != 8) {
        size = 1;
    }

    u64 value = 0;
    auto read_fifo = [&]() -> u8 {
        if (state_.fifo_index < state_.regs.response_size) {
            auto byte = state_.regs.data_fifo[state_.fifo_index++];

            if (state_.fifo_index >= state_.regs.response_size)
                state_.regs.sts &= ~TPM_STS_DATA_AVAIL;
            return byte;
        }

        return 0;
    };
    auto read_u32_lane = [](u32 reg, u32 reg_offset) -> u8 {
        return static_cast<u8>((reg >> (reg_offset * 8)) & 0xff);
    };

    if (offset == 0x24) {
        for (u32 i = 0; i < size; ++i) {
            value |= static_cast<u64>(read_fifo()) << (i * 8);
        }
    } else {
        const u32 sts_value = (state_.regs.sts & 0xff) | ((state_.regs.burst_count & 0xffff) << 8);
        for (u32 i = 0; i < size; ++i) {
            u32 byte_offset = (offset + i) & 0xFFF;
            u8 byte = 0;

            if (byte_offset == 0x00) {
                byte = static_cast<u8>(state_.regs.access | TPM_ACCESS_ACTIVE_LOCALITY);
            } else if (byte_offset >= 0x18 && byte_offset <= 0x1B) {
                byte = read_u32_lane(sts_value, byte_offset - 0x18);
            } else if (byte_offset >= 0x30 && byte_offset <= 0x33) {
                byte = read_u32_lane(state_.regs.interface_id, byte_offset - 0x30);
            } else if (byte_offset >= 0x14 && byte_offset <= 0x17) {
                byte = read_u32_lane(state_.regs.interface_capability, byte_offset - 0x14);
            } else if (byte_offset >= 0xF00 && byte_offset <= 0xF03) {
                byte = read_u32_lane(state_.regs.did_vid, byte_offset - 0xF00);
            } else if (byte_offset == 0xF04) {
                byte = state_.regs.rid;
            }

            value |= static_cast<u64>(byte) << (i * 8);
        }
    }

    KeReleaseSpinLock(&lock_, irql);
    return value;
}

void tpm::handle_write(u64 pa, u32 offset, u64 value, u32 size) {
    KIRQL irql;
    bool run_command = false;
    KeAcquireSpinLock(&lock_, &irql);
    state_.locality = (pa >> 12) & 0x7;
    offset &= 0xFFF;

    if (size != 1 && size != 2 && size != 4 && size != 8) {
        size = 1;
    }

    auto write_access = [&](u8 byte) -> void {
        auto locality = static_cast<u8>((pa >> 12) & 0x7);

        if (byte & TPM_ACCESS_REQUEST_USE) {
            if (state_.locality == 0xFF) {
                state_.locality = locality;
                state_.regs.access |= TPM_ACCESS_ACTIVE_LOCALITY;
                state_.regs.access &= ~TPM_ACCESS_REQUEST_USE;
            } else if (state_.locality != locality) {
                state_.regs.access |= TPM_ACCESS_REQUEST_USE;
            }
        }

        if (byte & TPM_ACCESS_ACTIVE_LOCALITY) {
            if (state_.locality == locality) {
                state_.regs.access &= ~TPM_ACCESS_ACTIVE_LOCALITY;
                state_.locality = 0xFF;
            }
        }
    };
    auto write_status = [&](u8 byte) -> void {
        if (byte & TPM_STS_READY) {
            state_.fifo_index = 0;
            state_.regs.response_size = 0;
            RtlZeroMemory(state_.regs.data_fifo, sizeof(state_.regs.data_fifo));
            state_.regs.sts |= TPM_STS_VALID | TPM_STS_READY;
            state_.regs.sts &= ~(TPM_STS_DATA_AVAIL | TPM_STS_EXPECT);
            state_.expect_data = true;
        }

        if (byte & TPM_STS_GO) {
            if (!(state_.regs.sts & TPM_STS_EXPECT)) {
                run_command = true;
            }
        }
    };
    auto write_fifo = [&](u8 byte) -> void {
        if (state_.fifo_index < sizeof(state_.regs.data_fifo)) {
            state_.regs.data_fifo[state_.fifo_index++] = byte;
            state_.regs.sts |= TPM_STS_EXPECT;

            if (state_.fifo_index >= sizeof(TPM2_COMMAND_HEADER)) {
                auto* hdr = reinterpret_cast<TPM2_COMMAND_HEADER*>(state_.regs.data_fifo);
                u32 cmd_size = _byteswap_ulong(hdr->paramSize);

                if (state_.fifo_index >= cmd_size)
                    state_.regs.sts &= ~TPM_STS_EXPECT;
            }
        }
    };

    if (offset == 0x24) {
        for (u32 i = 0; i < size; ++i) {
            write_fifo(static_cast<u8>((value >> (i * 8)) & 0xff));
        }
    } else {
        for (u32 i = 0; i < size; ++i) {
            u32 byte_offset = (offset + i) & 0xFFF;
            u8 byte = static_cast<u8>((value >> (i * 8)) & 0xff);

            if (byte_offset == 0x00) {
                write_access(byte);
            } else if (byte_offset == 0x18) {
                write_status(byte);
            }
        }
    }

    KeReleaseSpinLock(&lock_, irql);

    if (run_command) {
        process_command();
    }
}

TPM_RC tpm::validate_size() {
    auto* hdr = reinterpret_cast<TPM2_COMMAND_HEADER*>(state_.regs.data_fifo);
    u32 s = _byteswap_ulong(hdr->paramSize);
    return (s >= sizeof(TPM2_COMMAND_HEADER) && s <= 4096) ? TPM_RC_SUCCESS : TPM_RC_COMMAND_SIZE;
}

TPM_RC tpm::validate_locality() {
    return (state_.locality <= 4) ? TPM_RC_SUCCESS : TPM_RC_LOCALITY;
}

void tpm::process_command() {
    auto* hdr = reinterpret_cast<TPM2_COMMAND_HEADER*>(state_.regs.data_fifo);
    u32 cmd = _byteswap_ulong(hdr->commandCode);
    TPM_RC rc = validate_size();

    if (rc != TPM_RC_SUCCESS) {
        send_error(rc);
        return;
    }

    rc = validate_locality();

    if (rc != TPM_RC_SUCCESS) {
        send_error(rc);
        return;
    }

    switch (cmd) {
    case TPM_CC_Startup:
        vtpm_process_startup();
        break;
    case TPM_CC_SelfTest:
        vtpm_process_self_test();
        break;
    case TPM_CC_GetCapability:
        vtpm_process_get_capability();
        break;
    case TPM_CC_GetRandom:
        vtpm_process_get_random();
        break;
    case TPM_CC_ReadPublic:
        vtpm_process_read_public();
        break;
    case TPM_CC_NV_ReadPublic:
        vtpm_process_nv_read_public();
        break;
    case TPM_CC_NV_Read:
        vtpm_process_nv_read();
        break;
    case TPM_CC_NV_Write:
        vtpm_process_nv_write();
        break;
    case TPM_CC_RSA_Encrypt:
        vtpm_process_rsa_encrypt();
        break;
    case TPM_CC_HashSequenceStart:
        vtpm_process_hash_sequence_start();
        break;
    case TPM_CC_Hash:
        vtpm_process_hash();
        break;
    case TPM_CC_Create:
        vtpm_process_create();
        break;
    case TPM_CC_CreatePrimary:
        vtpm_process_create_primary();
        break;
    case TPM_CC_StartAuthSession:
        vtpm_process_start_auth_session();
        break;
    case TPM_CC_FlushContext:
        vtpm_process_flush_context();
        break;
    case TPM_CC_CertifyCreation:
        vtpm_process_certify_creation();
        break;
    case TPM_CC_Certify:
        vtpm_process_certify();
        break;
    case TPM_CC_Quote:
        vtpm_process_quote();
        break;
    case TPM_CC_VerifySignature:
        vtpm_process_verify_signature();
        break;
    case TPM_CC_GetTestResult:
        vtpm_process_get_test_result();
        break;
    case TPM_CC_PCR_Read:
        vtpm_process_pcr_read();
        break;
    case TPM_CC_PCR_Event:
        vtpm_process_pcr_event();
        break;
    case TPM_CC_PCR_Extend:
        vtpm_process_pcr_extend();
        break;
    case TPM_CC_ReadClock:
        vtpm_process_read_clock();
        break;
    case TPM_CC_PolicySecret:
        vtpm_process_policy_secret();
        break;
    case TPM_CC_PolicyGetDigest:
        vtpm_process_policy_get_digest();
        break;
    case TPM_CC_GetTime:
        vtpm_process_get_time();
        break;
    case TPM_CC_Clear:
        vtpm_process_clear();
        break;
    case TPM_CC_Load:
        vtpm_process_load();
        break;
    case TPM_CC_Unseal:
        vtpm_process_unseal();
        break;
    case TPM_CC_Sign:
        vtpm_process_sign();
        break;
    case TPM_CC_ActivateCredential:
        vtpm_process_activate_credential();
        break;
    case TPM_CC_MakeCredential:
        vtpm_process_make_credential();
        break;
    case TPM_CC_NV_DefineSpace:
        vtpm_process_nv_define_space();
        break;
    case TPM_CC_NV_UndefineSpace:
        vtpm_process_nv_undefine_space();
        break;
    case TPM_CC_EvictControl:
        vtpm_process_evict_control();
        break;
    case TPM_CC_ObjectChangeAuth:
        vtpm_process_object_change_auth();
        break;
    case TPM_CC_PolicyPCR:
        vtpm_process_policy_pcr();
        break;
    case TPM_CC_PolicyCommandCode:
        vtpm_process_policy_command_code();
        break;
    case TPM_CC_PolicyAuthValue:
        vtpm_process_policy_auth_value();
        break;
    case TPM_CC_PolicyOR:
        vtpm_process_policy_or();
        break;
    default:
        vtpm_process_default(cmd);
        break;
    }
}

void tpm::vtpm_process_startup() {
    write_response_header(state_.regs.data_fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    state_.regs.sts |= TPM_STS_READY;
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_self_test() {
    write_response_header(state_.regs.data_fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_get_capability() {
    u8* fifo = state_.regs.data_fifo;
    u32 capability = _byteswap_ulong(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    u32 property = _byteswap_ulong(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER) + 4));
    u32 property_count = _byteswap_ulong(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER) + 8));

    if (capability == TPM_CAP_TPM_PROPERTIES) {
        struct {
            u32 p;
            u32 v;
        } t[] = {
            {0x100, 0x322E3000}, {0x101, 0x00000000}, {0x102, 0x0000008A}, {0x103, 0x0000001C}, {0x104, 0x000007E5},
            {0x105, 0x414D4400}, {0x106, 0x414D4400}, {0x107, 0x00000000}, {0x108, 0x00000000}, {0x109, 0x00000000},
            {0x10A, 0x00000001}, {0x10B, 0x0003005E}, {0x10C, 0x00020005}, {0x10D, 0x00000400}, {0x10E, 0x00000006},
            {0x10F, 0x00000007}, {0x110, 0x00000003}, {0x111, 0x00000040}, {0x112, 0x00000018}, {0x113, 0x00000003},
            {0x114, 0x0000FFFF}, {0x116, 0x00000000}, {0x117, 0x00000800}, {0x118, 0x00000006}, {0x119, 0x00001000},
            {0x11A, 0x0000000C}, {0x11B, 0x00000006}, {0x11C, 0x00000100}, {0x11D, 0x000000FF}, {0x11E, 0x00001000},
            {0x11F, 0x00001000}, {0x120, 0x00000030}, {0x121, 0x000009F0}, {0x122, 0x0000014C}, {0x123, 0x322E3000},
            {0x124, 0x00000000}, {0x125, 0x00000105}, {0x126, 0x0000001C}, {0x127, 0x000007E5}, {0x128, 0x00000080},
            {0x129, 0x0000006E}, {0x12A, 0x0000006D}, {0x12B, 0x00000001}, {0x12C, 0x00000400}, {0x12D, 0x00000001},
            {0x12E, 0x00000400}, {0x200, 0x00000404}, {0x201, 0x8000000F}, {0x202, 0x00000006}, {0x203, 0x00000000},
            {0x204, 0x00000003}, {0x205, 0x00000000}, {0x206, 0x00000040}, {0x207, 0x00000005}, {0x208, 0x00000003},
            {0x209, 0x00000008}, {0x20A, 0x00000002}, {0x20B, 0x00000018}, {0x20C, 0x00000000}, {0x20D, 0x00000003},
            {0x20E, 0x00000000}, {0x20F, 0x0000001F}, {0x210, 0x00000258}, {0x211, 0x00015180}, {0x212, 0x00000000},
            {0x213, 0x00000000}, {0x214, 0x00000000},
        };
        u32 n = 0;

        for (u32 i = 0; i < ARRAYSIZE(t); i++)
            if (t[i].p >= property && n < property_count) {
                n++;
            }

        u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 1 + 4 + 4 + n * 8;

        if (rs > 4096) {
            n = 0;
            rs = sizeof(TPM2_RESPONSE_HEADER) + 9;
        }

        RtlZeroMemory(fifo, rs);
        u8* p = fifo;
        write_response_header(p, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
        p += sizeof(TPM2_RESPONSE_HEADER);
        *p = 0;
        p += 1;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TPM_CAP_TPM_PROPERTIES);
        p += 4;
        u8* cnt = p;
        p += 4;
        u32 idx = 0;

        for (u32 i = 0; i < ARRAYSIZE(t) && idx < n; i++) {
            if (t[i].p >= property) {
                *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(t[i].p);
                p += 4;
                *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(t[i].v);
                p += 4;
                idx++;
            }
        }

        *reinterpret_cast<u32*>(cnt) = big_endian_to_little_endian32(idx);
        rs = sizeof(TPM2_RESPONSE_HEADER) + 1 + 4 + 4 + idx * 8;
        reinterpret_cast<TPM2_RESPONSE_HEADER*>(fifo)->paramSize = big_endian_to_little_endian32(rs);
        send_response(rs);
        return;
    }

    if (capability == TPM_CAP_HANDLES) {
        u32 h[4];
        u32 hc = 0;

        if ((property & 0xFF000000) == 0x81000000 || property == 0x81000000) {
            if (property <= 0x81000001 && hc < property_count) {
                h[hc++] = 0x81000001;
            }

            if (property <= 0x81010001 && hc < property_count) {
                h[hc++] = 0x81010001;
            }
        }

        u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 1 + 4 + 4 + hc * 4;
        RtlZeroMemory(fifo, rs);
        u8* p = fifo;
        write_response_header(p, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
        p += sizeof(TPM2_RESPONSE_HEADER);
        *p = 0;
        p += 1;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TPM_CAP_HANDLES);
        p += 4;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(hc);
        p += 4;

        for (u32 i = 0; i < hc; i++) {
            *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(h[i]);
            p += 4;
        }

        send_response(rs);
        return;
    }

    if (capability == TPM_CAP_COMMANDS) {
        struct {
            u32 cc;
            u32 at;
        } sc[] = {
            {0x126, 0x126}, {0x131, 0x131}, {0x143, 0x143}, {0x144, 0x144}, {0x153, 0x153},
            {0x165, 0x165}, {0x169, 0x169}, {0x173, 0x173}, {0x174, 0x174}, {0x176, 0x176},
            {0x17A, 0x17A}, {0x17B, 0x17B}, {0x17C, 0x17C}, {0x17E, 0x17E},
        };
        u32 cc = 0, si = 0;

        for (u32 i = 0; i < ARRAYSIZE(sc); i++) {
            if (sc[i].cc >= property) {
                if (!cc) {
                    si = i;
                }

                cc++;

                if (cc >= property_count) {
                    break;
                }
            }
        }

        u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 1 + 4 + 4 + cc * 4;
        RtlZeroMemory(fifo, rs);
        u8* p = fifo;
        write_response_header(p, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
        p += sizeof(TPM2_RESPONSE_HEADER);
        *p = 0;
        p += 1;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TPM_CAP_COMMANDS);
        p += 4;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(cc);
        p += 4;

        for (u32 i = 0; i < cc; i++) {
            *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(sc[si + i].at);
            p += 4;
        }

        send_response(rs);
        return;
    }

    if (capability == TPM_CAP_PCRS) {
        struct {
            u16 alg;
            u32 bit;
        } pcr_banks[] = {
            {0x0004, 0x01},
            {0x000B, 0x02},
            {0x000C, 0x04},
            {0x000D, 0x08},
        };
        u32 bank_count = 0;

        for (u32 i = 0; i < ARRAYSIZE(pcr_banks); i++)
            if (state_.supported_banks & pcr_banks[i].bit) {
                bank_count++;
            }

        if (bank_count == 0) {
            bank_count = 1;
        }

        u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 1 + 4 + 4 + bank_count * (2 + 1 + 3);
        RtlZeroMemory(fifo, rs);
        u8* p = fifo;
        write_response_header(p, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
        p += sizeof(TPM2_RESPONSE_HEADER);
        *p = 0;
        p += 1;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TPM_CAP_PCRS);
        p += 4;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(bank_count);
        p += 4;

        if (state_.supported_banks == 0) {
            *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0x000B);
            p += 2;
            *p = 3;
            p += 1;
            p[0] = 0xFF;
            p[1] = 0xFF;
            p[2] = 0xFF;
            p += 3;
        } else {
            for (u32 i = 0; i < ARRAYSIZE(pcr_banks); i++) {
                if (state_.supported_banks & pcr_banks[i].bit) {
                    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(pcr_banks[i].alg);
                    p += 2;
                    *p = 3;
                    p += 1;
                    p[0] = 0xFF;
                    p[1] = 0xFF;
                    p[2] = 0xFF;
                    p += 3;
                }
            }
        }

        send_response(rs);
        return;
    }

    if (capability == TPM_CAP_ALGS) {
        struct {
            u16 a;
            u32 at;
        } al[] = {
            {0x0001, 0x00000009}, {0x0004, 0x00000004}, {0x0005, 0x00000008},
            {0x0006, 0x00000003}, {0x000B, 0x00000004}, {0x000C, 0x00000004},
            {0x000D, 0x00000004}, {0x0010, 0x00000000}, {0x0043, 0x00000000},
        };
        u32 c = 0;

        for (u32 i = 0; i < ARRAYSIZE(al); i++)
            if (al[i].a >= property && c < property_count) {
                c++;
            }

        u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 1 + 4 + 4 + c * 6;
        RtlZeroMemory(fifo, rs);
        u8* p = fifo;
        write_response_header(p, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
        p += sizeof(TPM2_RESPONSE_HEADER);
        *p = 0;
        p += 1;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TPM_CAP_ALGS);
        p += 4;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(c);
        p += 4;
        u32 idx = 0;

        for (u32 i = 0; i < ARRAYSIZE(al) && idx < c; i++) {
            if (al[i].a >= property) {
                *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(al[i].a);
                p += 2;
                *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(al[i].at);
                p += 4;
                idx++;
            }
        }

        send_response(rs);
        return;
    }

    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 1 + 4 + 4;
    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);
    *p = 0;
    p += 1;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(capability);
    p += 4;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(0);
    send_response(rs);
}

void tpm::vtpm_process_get_random() {
    u8* fifo = state_.regs.data_fifo;
    u16 req = big_endian_to_little_endian16(*reinterpret_cast<u16*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    if (req > TPM_MAX_RNG_BYTES) {
        req = TPM_MAX_RNG_BYTES;
    }

    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 2 + req;
    RtlZeroMemory(fifo, rs);
    write_response_header(fifo, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    u8* p = fifo + sizeof(TPM2_RESPONSE_HEADER);
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(req);
    p += 2;
    LARGE_INTEGER perf;
    KeQueryPerformanceCounter(&perf);
    u64 seed = perf.QuadPart;
    lcg_fill(seed, p, req);
    send_response(rs);
}

void tpm::vtpm_process_read_public() {
    u8* fifo = state_.regs.data_fifo;
    u32 handle = 0;
    u32 cs = _byteswap_ulong(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->paramSize);

    if (cs >= sizeof(TPM2_COMMAND_HEADER) + 4)
        handle = big_endian_to_little_endian32(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));

    object_slot_t* slot = find_slot(handle);
    bool is_srk = (handle == 0x81000001 || handle == 0x80000001);
    bool is_ek = (handle == 0x81010001 || handle == 0x80000000);

    if (!slot && !is_srk && !is_ek && (handle & 0xFF000000) == 0x81000000) {
        write_response_header(fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), 0x0000008B);
        send_response(sizeof(TPM2_RESPONSE_HEADER));
        return;
    }

    u8 public_copy[600];
    u16 public_size = 0;

    if (slot) {
        public_size = slot->public_size;
        RtlCopyMemory(public_copy, slot->public_area, public_size);
    } else {
        constexpr u16 KEY_SIZE = 256;
        u32 aps = is_srk ? 0 : 32;
        public_size = (u16)(2 + 2 + 4 + 2 + aps + 2 + 2 + 2 + 2 + 2 + 4 + 2 + KEY_SIZE);
        u8* w = public_copy;
        w = is_srk ? write_srk_rsa_public(w) : write_ek_rsa_public(w);
        // write_*_rsa_public emits u16 size + TPMT_PUBLIC; strip the size
        RtlMoveMemory(public_copy, public_copy + 2, public_size);
    }

    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (2 + public_size) + (2 + 34) + (2 + 34);

    if (rs > 4096) {
        write_response_header(fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
        send_response(sizeof(TPM2_RESPONSE_HEADER));
        return;
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    // outPublic
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(public_size);
    p += 2;
    RtlCopyMemory(p, public_copy, public_size);
    p += public_size;

    // name
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(34);
    p += 2;
    p = write_computed_name(p, public_copy, public_size);

    // qualifiedName (approximated with the name; sufficient for NGC/TBS use)
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(34);
    p += 2;
    p = write_computed_name(p, public_copy, public_size);

    send_response(rs);
}

void tpm::vtpm_process_nv_read_public() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    u32 nvi = 0;
    u32 cs = _byteswap_ulong(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->paramSize);

    if (cs >= sizeof(TPM2_COMMAND_HEADER) + 4)
        nvi = big_endian_to_little_endian32(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    auto* nv = find_nv_index(nvi);

    if (nvi == 0x01C00002 && nv && nv->size > 0) {
        constexpr u32 NVP = 4 + 2 + 4 + 2 + 2;
        u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 2 + NVP + 2 + 2 + 32;

        if (rs > 4096) {
            write_response_header(fifo, ctag, sizeof(TPM2_RESPONSE_HEADER), 0x0000018B);
            send_response(sizeof(TPM2_RESPONSE_HEADER));
            return;
        }

        RtlZeroMemory(fifo, rs);
        u8* p = fifo;
        write_response_header(p, ctag, rs, TPM_RC_SUCCESS);
        p += sizeof(TPM2_RESPONSE_HEADER);
        *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(NVP);
        p += 2;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(0x01C00002);
        p += 4;
        *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0x000B);
        p += 2;
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(0x62060001);
        p += 4;
        *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
        p += 2;
        *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16((u16)nv->size);
        p += 2;
        *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(2 + 32);
        p += 2;
        *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0x000B);
        p += 2;
        u64 seed = 0x4E564E414D453031ULL;
        lcg_fill(seed, p, 32);
        send_response(rs);
        return;
    }

    write_response_header(fifo, ctag, sizeof(TPM2_RESPONSE_HEADER), 0x0000018B);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_nv_read() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool has_sessions = (ctag == TPM_ST_SESSIONS);
    u8* cp = fifo + sizeof(TPM2_COMMAND_HEADER);
    cp += sizeof(u32);
    u32 nvi = big_endian_to_little_endian32(*reinterpret_cast<u32*>(cp));
    cp += 4;

    if (has_sessions) {
        u32 aas = big_endian_to_little_endian32(*reinterpret_cast<u32*>(cp));
        cp += 4 + aas;
    }

    u16 rsz = 0, roff = 0;
    u32 total = _byteswap_ulong(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->paramSize);

    if ((u32)(cp - fifo) + 4 <= total) {
        rsz = big_endian_to_little_endian16(*reinterpret_cast<u16*>(cp));
        cp += 2;
        roff = big_endian_to_little_endian16(*reinterpret_cast<u16*>(cp));
    }

    auto* nv = find_nv_index(nvi);

    if (nv && nv->size > 0) {
        if (roff >= nv->size) {
            write_response_header(fifo, ctag, sizeof(TPM2_RESPONSE_HEADER), 0x0000009A);
            send_response(sizeof(TPM2_RESPONSE_HEADER));
            return;
        }

        u32 avail = nv->size - roff;

        if (rsz > avail) {
            rsz = (u16)avail;
        }

        if (rsz > 1024) {
            rsz = 1024;
        }

        constexpr u32 ARS = 2 + 32 + 1 + 2;
        u32 ds = 2 + rsz;
        u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (has_sessions ? 4 : 0) + ds + (has_sessions ? ARS : 0);

        if (rs > 4096) {
            write_response_header(fifo, ctag, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
            send_response(sizeof(TPM2_RESPONSE_HEADER));
            return;
        }

        RtlZeroMemory(fifo, rs);
        u8* p = fifo;
        write_response_header(p, has_sessions ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
        p += sizeof(TPM2_RESPONSE_HEADER);

        if (has_sessions) {
            *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(ds);
            p += 4;
        }

        *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(rsz);
        p += 2;
        RtlCopyMemory(p, nv->data + roff, rsz);
        p += rsz;

        if (has_sessions) {
            write_auth_session_response(p);
        }

        send_response(rs);
        return;
    }

    write_response_header(fifo, ctag, sizeof(TPM2_RESPONSE_HEADER), 0x0000018B);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_nv_write() {
    u8* fifo = state_.regs.data_fifo;
    u32 nvi = _byteswap_ulong(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    u32 as = _byteswap_ulong(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER) + 4));
    u8* par = fifo + sizeof(TPM2_COMMAND_HEADER) + 8 + as;
    u16 off = _byteswap_ushort(*reinterpret_cast<u16*>(par));
    u16 dsz = _byteswap_ushort(*reinterpret_cast<u16*>(par + 2));
    u8* data = par + 4;
    auto* nv = find_nv_index(nvi);

    if (!nv && nvi >= 0x01C00000 && nvi <= 0x01FFFFFF) {
        nv = create_nv_index(nvi, 0x42000000, 0);
    }

    if (!nv) {
        send_error(TPM_RC_HANDLE);
        return;
    }

    u32 end = static_cast<u32>(off) + static_cast<u32>(dsz);

    if (end > MAX_NV_SIZE) {
        send_error(TPM_RC_NV_RANGE);
        return;
    }

    memcpy(nv->data + off, data, dsz);

    if (end > nv->size) {
        nv->size = end;
    }

    write_response_header(fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_rsa_encrypt() {
    constexpr u16 KS = 256;
    u8* fifo = state_.regs.data_fifo;
    u8* cp = fifo + sizeof(TPM2_COMMAND_HEADER) + 4;
    u16 ms = big_endian_to_little_endian16(*reinterpret_cast<u16*>(cp));
    cp += 2;
    u32 total = _byteswap_ulong(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->paramSize);

    if (ms > KS || sizeof(TPM2_COMMAND_HEADER) + 6 + ms > total) {
        ms = 0;
    }

    u8 msg[256];
    RtlZeroMemory(msg, sizeof(msg));

    if (ms > 0) {
        RtlCopyMemory(msg, cp, ms);
    }

    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 2 + KS;
    RtlZeroMemory(fifo, rs);
    write_response_header(fifo, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    u8* p = fifo + sizeof(TPM2_RESPONSE_HEADER);
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(KS);
    p += 2;
    LARGE_INTEGER perf;
    KeQueryPerformanceCounter(&perf);
    u64 seed = perf.QuadPart;

    for (u16 i = 0; i < ms && i < 8; i++)
        seed ^= ((u64)msg[i]) << (i * 8);
    lcg_fill(seed, p, KS);
    p[0] &= 0x7F;
    send_response(rs);
}

void tpm::vtpm_process_hash_sequence_start() {
    u8* fifo = state_.regs.data_fifo;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 4;
    RtlZeroMemory(fifo, rs);
    write_response_header(fifo, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    *reinterpret_cast<u32*>(fifo + sizeof(TPM2_RESPONSE_HEADER)) = big_endian_to_little_endian32(0x80000001);
    send_response(rs);
}

void tpm::vtpm_write_attestation_response(u16 attestation_type, u32 salt) {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);

    u8 attest[512] = {};
    u8* ap = attest;
    *reinterpret_cast<u32*>(ap) = big_endian_to_little_endian32(TPM_GENERATED_VALUE);
    ap += 4;
    *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(attestation_type);
    ap += 2;
    *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(0);
    ap += 2;
    *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(0);
    ap += 2;

    LARGE_INTEGER perf;
    KeQueryPerformanceCounter(&perf);
    u64 seed_base = perf.QuadPart ^ ((u64)salt << 32) ^ 0x4154544553545043ULL;
    u64 clock = perf.QuadPart;

    *reinterpret_cast<u64*>(ap) = _byteswap_uint64(clock);
    ap += 8;
    *reinterpret_cast<u32*>(ap) = big_endian_to_little_endian32(state_.pcr_counter);
    ap += 4;
    *reinterpret_cast<u32*>(ap) = big_endian_to_little_endian32(state_.pcr_counter / 2);
    ap += 4;
    *ap++ = 1;
    *reinterpret_cast<u64*>(ap) = _byteswap_uint64(0x0003005E00020005ULL);
    ap += 8;

    auto fill_digest = [&](u8* dst, u16 size, u64 extra) {
        u64 seed = seed_base ^ extra;
        for (u16 i = 0; i < size; ++i) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            dst[i] = (u8)((seed >> 33) ^ state_.pcr_sha256[i % IMPLEMENTATION_PCR][i % 32]);
        }
    };

    if (attestation_type == TPM_ST_ATTEST_QUOTE) {
        *reinterpret_cast<u32*>(ap) = big_endian_to_little_endian32(1);
        ap += 4;
        *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(TPM_ALG_SHA256);
        ap += 2;
        *ap++ = 3;
        *ap++ = 0x95;
        *ap++ = 0x00;
        *ap++ = 0x00;
        *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(32);
        ap += 2;
        fill_digest(ap, 32, 0x51554F5445ULL);
        ap += 32;
    } else if (attestation_type == TPM_ST_ATTEST_CERTIFY) {
        *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(34);
        ap += 2;
        *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(TPM_ALG_SHA256);
        ap += 2;
        fill_digest(ap, 32, 0x434552544E414D45ULL);
        ap += 32;
        *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(34);
        ap += 2;
        *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(TPM_ALG_SHA256);
        ap += 2;
        fill_digest(ap, 32, 0x51434E414D45ULL);
        ap += 32;
    } else if (attestation_type == TPM_ST_ATTEST_CREATION) {
        *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(34);
        ap += 2;
        *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(TPM_ALG_SHA256);
        ap += 2;
        fill_digest(ap, 32, 0x435245414E414D45ULL);
        ap += 32;
        *reinterpret_cast<u16*>(ap) = big_endian_to_little_endian16(32);
        ap += 2;
        fill_digest(ap, 32, 0x4352454148415348ULL);
        ap += 32;
    } else if (attestation_type == TPM_ST_ATTEST_TIME) {
        *reinterpret_cast<u64*>(ap) = _byteswap_uint64(clock);
        ap += 8;
        *reinterpret_cast<u64*>(ap) = _byteswap_uint64(clock);
        ap += 8;
        *reinterpret_cast<u32*>(ap) = big_endian_to_little_endian32(state_.pcr_counter);
        ap += 4;
        *reinterpret_cast<u32*>(ap) = big_endian_to_little_endian32(state_.pcr_counter / 2);
        ap += 4;
        *ap++ = 1;
        *reinterpret_cast<u64*>(ap) = _byteswap_uint64(0x0003005E00020005ULL);
        ap += 8;
    }

    u16 attest_size = (u16)(ap - attest);
    constexpr u16 SIG_SIZE = 256;
    constexpr u32 TPMT_SIG_SIZE = 2 + 2 + 2 + SIG_SIZE;
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 param_size = 2 + attest_size + TPMT_SIG_SIZE;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + param_size + (hs ? AR : 0);

    if (rs > sizeof(state_.regs.data_fifo)) {
        send_error(TPM_RC_FAILURE);
        return;
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(param_size);
        p += 4;
    }

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(attest_size);
    p += 2;
    RtlCopyMemory(p, attest, attest_size);
    p += attest_size;

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(TPM_ALG_RSASSA);
    p += 2;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(TPM_ALG_SHA256);
    p += 2;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(SIG_SIZE);
    p += 2;
    fill_digest(p, SIG_SIZE, 0x534947ULL ^ attestation_type);
    p[0] &= 0x7F;
    p += SIG_SIZE;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_hash() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);
    u32 cmd_size = big_endian_to_little_endian32(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->paramSize);

    u16 hash_alg = TPM_ALG_SHA256;
    if (cmd_size >= sizeof(TPM2_COMMAND_HEADER) + 2) {
        u8* cp = fifo + sizeof(TPM2_COMMAND_HEADER);
        u8* end = fifo + min(cmd_size, (u32)sizeof(state_.regs.data_fifo));
        u16 data_size = big_endian_to_little_endian16(*reinterpret_cast<u16*>(cp));
        cp += 2;
        if (cp + data_size + 2 <= end) {
            cp += data_size;
            hash_alg = big_endian_to_little_endian16(*reinterpret_cast<u16*>(cp));
        }
    }

    u16 digest_size = 32;
    switch (hash_alg) {
    case TPM_ALG_SHA1: digest_size = 20; break;
    case TPM_ALG_SHA256: digest_size = 32; break;
    case TPM_ALG_SHA384: digest_size = 48; break;
    case TPM_ALG_SHA512: digest_size = 64; break;
    default: hash_alg = TPM_ALG_SHA256; digest_size = 32; break;
    }

    constexpr u32 TICKET_SIZE = 2 + 4 + 2;
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 param_size = 2 + digest_size + TICKET_SIZE;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + param_size + (hs ? AR : 0);

    if (rs > sizeof(state_.regs.data_fifo)) {
        send_error(TPM_RC_FAILURE);
        return;
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(param_size);
        p += 4;
    }

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(digest_size);
    p += 2;
    u64 seed = __rdtsc() ^ hash_alg ^ 0x48415348ULL;
    for (u16 i = 0; i < digest_size; ++i) {
        p[i] = (u8)(lcg_byte(seed) ^ state_.pcr_sha256[i % IMPLEMENTATION_PCR][i % 32]);
    }
    p += digest_size;

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(TPM_ST_HASHCHECK);
    p += 2;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TPM_RH_NULL);
    p += 4;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
    p += 2;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_certify_creation() {
    vtpm_write_attestation_response(TPM_ST_ATTEST_CREATION, TPM_CC_CertifyCreation);
}

void tpm::vtpm_process_certify() {
    vtpm_write_attestation_response(TPM_ST_ATTEST_CERTIFY, TPM_CC_Certify);
}

void tpm::vtpm_process_quote() {
    vtpm_write_attestation_response(TPM_ST_ATTEST_QUOTE, TPM_CC_Quote);
}

void tpm::vtpm_process_verify_signature() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);
    constexpr u32 TICKET_SIZE = 2 + 4 + 2;
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + TICKET_SIZE + (hs ? AR : 0);

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TICKET_SIZE);
        p += 4;
    }

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(TPM_ST_VERIFIED);
    p += 2;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TPM_RH_NULL);
    p += 4;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
    p += 2;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_create() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);

    // handles: parentHandle (4 bytes)
    u8* params = params_after_auth(fifo, 4, hs);

    // inSensitive: TPM2B_SENSITIVE_CREATE { u16 size; TPMS { userAuth, data } }
    u16 sens_size = big_endian_to_little_endian16(*reinterpret_cast<u16*>(params));
    u8* sp = params + 2;
    u8* sens_end = sp + sens_size;

    u16 auth_len = 0;
    const u8* auth = nullptr;
    u16 data_len = 0;
    const u8* data = nullptr;
    if (sp + 2 <= sens_end) {
        auth_len = big_endian_to_little_endian16(*reinterpret_cast<u16*>(sp));
        auth = sp + 2;
        sp += 2 + auth_len;
        if (sp + 2 <= sens_end) {
            data_len = big_endian_to_little_endian16(*reinterpret_cast<u16*>(sp));
            data = sp + 2;
            sp += 2 + data_len;
        }
    }

    // inPublic: TPM2B_PUBLIC
    u16 pub_size = big_endian_to_little_endian16(*reinterpret_cast<u16*>(sp));
    const u8* in_public = sp + 2;
    if (pub_size < 12 || pub_size > 600) {
        send_error(TPM_RC_SIZE);
        return;
    }

    const u16 type_alg = big_endian_to_little_endian16(*reinterpret_cast<const u16*>(in_public));

    // Walk to the trailing 'unique' field:
    // type(2) nameAlg(2) attributes(4) authPolicy(TPM2B) parms(...)
    u32 off = 2 + 2 + 4;
    u16 policy_len = big_endian_to_little_endian16(*reinterpret_cast<const u16*>(in_public + off));
    off += 2 + policy_len;

    const bool is_rsa = (type_alg == 0x0001);
    const bool is_keyed_hash = (type_alg == 0x0008);
    u32 unique_off = 0;

    if (is_rsa) {
        u16 sym_alg = big_endian_to_little_endian16(*reinterpret_cast<const u16*>(in_public + off));
        off += 2;
        if (sym_alg != 0x0010) // TPM_ALG_NULL
            off += 4;          // keyBits + mode
        u16 scheme_alg = big_endian_to_little_endian16(*reinterpret_cast<const u16*>(in_public + off));
        off += 2;
        if (scheme_alg != 0x0010)
            off += 2;          // scheme hash alg
        off += 2 + 4;          // keyBits + exponent
        unique_off = off;
    } else if (is_keyed_hash) {
        u16 scheme_alg = big_endian_to_little_endian16(*reinterpret_cast<const u16*>(in_public + off));
        off += 2;
        if (scheme_alg != 0x0010)
            off += 2;
        unique_off = off;
    } else {
        send_error(TPM_RC_VALUE); // ECC and other types are not emulated
        return;
    }

    if (unique_off > pub_size || unique_off + 2 + 256 > 600) {
        send_error(TPM_RC_VALUE);
        return;
    }

    u32 new_handle = 0;
    object_slot_t* slot = alloc_slot(&new_handle);
    if (!slot) {
        send_error(TPM_RC_OBJECT_HANDLES);
        return;
    }

    if (is_rsa) {
        u8 modulus[256];
        u8 prime1[128];
        u8 prime2[128];
        u8 exponent[4];
        u32 exponent_len = 0;

        auto* crypto = tpm_crypto::get();
        if (!crypto ||
            !NT_SUCCESS(crypto->rsa_generate_2048(modulus, prime1, prime2, exponent, &exponent_len))) {
            free_slot(new_handle);
            send_error(TPM_RC_FAILURE);
            return;
        }

        slot->is_rsa = true;
        slot->public_size = static_cast<u16>(unique_off + 2 + sizeof(modulus));
        RtlCopyMemory(slot->public_area, in_public, unique_off);
        u8* up = slot->public_area + unique_off;
        *reinterpret_cast<u16*>(up) = big_endian_to_little_endian16((u16)sizeof(modulus));
        RtlCopyMemory(up + 2, modulus, sizeof(modulus));

        // priv: expLen(2) + exp + n[256] + p[128] + q[128]
        u8* pv = slot->priv;
        *reinterpret_cast<u16*>(pv) = static_cast<u16>(exponent_len);
        pv += 2;
        RtlCopyMemory(pv, exponent, exponent_len);
        pv += exponent_len;
        RtlCopyMemory(pv, modulus, sizeof(modulus));
        pv += sizeof(modulus);
        RtlCopyMemory(pv, prime1, sizeof(prime1));
        pv += sizeof(prime1);
        RtlCopyMemory(pv, prime2, sizeof(prime2));
        slot->priv_len = static_cast<u16>(2 + exponent_len + 256 + 128 + 128);
    } else {
        // Sealed-data object: unique = digest of the payload; the payload is
        // the private part so Unseal can hand it back
        slot->is_rsa = false;
        slot->public_size = static_cast<u16>(unique_off + 2 + 32);
        RtlCopyMemory(slot->public_area, in_public, unique_off);
        u8* up = slot->public_area + unique_off;
        *reinterpret_cast<u16*>(up) = big_endian_to_little_endian16(32);

        u8 digest[32];
        auto* crypto = tpm_crypto::get();
        bool hashed = false;
        if (crypto && data && data_len)
            hashed = NT_SUCCESS(crypto->hash_sha256(data, data_len, digest));
        if (!hashed) {
            u64 s = state_.id_seed ^ 0x5345414C45444731ULL;
            lcg_fill(s, digest, sizeof(digest));
        }
        RtlCopyMemory(up + 2, digest, sizeof(digest));

        u16 payload = data_len > 256 ? 256 : data_len;
        if (data && payload)
            RtlCopyMemory(slot->priv, data, payload);
        slot->priv_len = payload;
    }

    slot->auth_len = auth_len > (u16)sizeof(slot->auth) ? (u16)sizeof(slot->auth) : auth_len;
    if (auth && slot->auth_len)
        RtlCopyMemory(slot->auth, auth, slot->auth_len);

    u8 blob[1280];
    u16 blob_len = marshal_blob(slot, blob);

    const u32 OP = 2 + blob_len;
    const u32 OPU = 2 + slot->public_size;
    constexpr u32 CD = 2, CH = 2 + 32, CT = 2 + 4 + 2;
    constexpr u32 AR = 2 + 32 + 1 + 2;
    const u32 PA = OP + OPU + CD + CH + CT;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + PA + (hs ? AR : 0);

    if (rs > 4096) {
        free_slot(new_handle);
        send_error(TPM_RC_FAILURE);
        return;
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(PA);
        p += 4;
    }

    // outPrivate: our opaque blob; the guest stores it in the NGC container
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(blob_len);
    p += 2;
    RtlCopyMemory(p, blob, blob_len);
    p += blob_len;

    // outPublic
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(slot->public_size);
    p += 2;
    RtlCopyMemory(p, slot->public_area, slot->public_size);
    p += slot->public_size;

    // creationData (empty), creationHash, creationTicket
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
    p += 2;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(32);
    p += 2;
    {
        u64 s = state_.id_seed ^ 0x4352454154494F4EULL ^ blob_len;
        lcg_fill(s, p, 32);
    }
    p += 32;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0x8021); // TPM_ST_CREATION
    p += 2;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(0x4000000B); // TPM_RH_OWNER
    p += 4;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
    p += 2;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}
void tpm::vtpm_process_create_primary() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);
    u32 hier = big_endian_to_little_endian32(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    bool is_srk = (hier == TPM_RH_OWNER || hier == TPM_RH_PLATFORM);
    constexpr u16 KS = 256;
    u32 aps = is_srk ? 0 : 32;
    u32 tpmt = 2 + 2 + 4 + 2 + aps + 2 + 2 + 2 + 2 + 2 + 4 + 2 + KS;
    u32 opu = 2 + tpmt;
    constexpr u32 CD = 2, CH = 2 + 32, CK = 2 + 4 + 2, NM = 2 + 2 + 32, AR = 2 + 32 + 1 + 2;
    u32 PA = opu + CD + CH + CK + NM;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 4 + (hs ? 4 : 0) + PA + (hs ? AR : 0);

    if (rs > 4096) {
        write_response_header(fifo, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER),
                              TPM_RC_SUCCESS);
        send_response(sizeof(TPM2_RESPONSE_HEADER));
        return;
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);
    u32 oh = is_srk ? 0x80000001 : 0x80000000;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(oh);
    p += 4;

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(PA);
        p += 4;
    }

    u8* pub_field = p;
    p = is_srk ? write_srk_rsa_public(p) : write_ek_rsa_public(p);
    const u8* pub_content = pub_field + 2;
    u32 pub_content_size = (u32)(p - pub_field) - 2;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
    p += 2;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(32);
    p += 2;
    LARGE_INTEGER perf;
    KeQueryPerformanceCounter(&perf);
    u64 seed = perf.QuadPart ^ (is_srk ? 0x53524B4841534830ULL : 0xDEADBEEFCAFE0131ULL);
    lcg_fill(seed, p, 32);
    p += 32;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0x8021);
    p += 2;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(hier);
    p += 4;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
    p += 2;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(2 + 32);
    p += 2;
    p = write_computed_name(p, pub_content, pub_content_size);

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_start_auth_session() {
    u8* fifo = state_.regs.data_fifo;
    constexpr u32 RS = sizeof(TPM2_RESPONSE_HEADER) + 4 + 2 + 32;
    RtlZeroMemory(fifo, RS);
    u8* p = fifo;
    write_response_header(p, TPM_ST_NO_SESSIONS, RS, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(0x02000000);
    p += 4;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(32);
    p += 2;
    LARGE_INTEGER perf;
    KeQueryPerformanceCounter(&perf);
    u64 seed = perf.QuadPart ^ 0xA0A1A2A3A4A5A6A7ULL;
    lcg_fill(seed, p, 32);
    send_response(RS);
}

void tpm::vtpm_process_flush_context() {
    u8* fifo = state_.regs.data_fifo;
    u32 flush_handle = big_endian_to_little_endian32(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    free_slot(flush_handle);
    write_response_header(fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_read_clock() {
    u8* fifo = state_.regs.data_fifo;
    constexpr u32 RS = sizeof(TPM2_RESPONSE_HEADER) + 8 + 8 + 4 + 4 + 1;
    RtlZeroMemory(fifo, RS);
    u8* p = fifo;
    write_response_header(p, TPM_ST_NO_SESSIONS, RS, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);
    LARGE_INTEGER perf;
    KeQueryPerformanceCounter(&perf);
    u64 tms = perf.QuadPart / 10;
    *(reinterpret_cast<u32*>(p) + 0) = big_endian_to_little_endian32((u32)(tms >> 32));
    *(reinterpret_cast<u32*>(p) + 1) = big_endian_to_little_endian32((u32)(tms & 0xFFFFFFFF));
    p += 8;
    u64 cms = tms + 1000000;
    *(reinterpret_cast<u32*>(p) + 0) = big_endian_to_little_endian32((u32)(cms >> 32));
    *(reinterpret_cast<u32*>(p) + 1) = big_endian_to_little_endian32((u32)(cms & 0xFFFFFFFF));
    p += 8;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(1);
    p += 4;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(0);
    p += 4;
    *p = 1;
    send_response(RS);
}

void tpm::vtpm_process_policy_secret() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);
    constexpr u32 PM = 2 + 2 + 4 + 2;
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + PM + (hs ? AR : 0);
    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(PM);
        p += 4;
    }

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
    p += 2;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0x8023);
    p += 2;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TPM_RH_ENDORSEMENT);
    p += 4;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
    p += 2;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_policy_get_digest() {
    u8* fifo = state_.regs.data_fifo;
    constexpr u32 RS = sizeof(TPM2_RESPONSE_HEADER) + 2 + 32;
    RtlZeroMemory(fifo, RS);
    u8* p = fifo;
    write_response_header(p, TPM_ST_NO_SESSIONS, RS, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(32);
    p += 2;
    RtlCopyMemory(p, EK_AUTH_POLICY, 32);
    send_response(RS);
}

void tpm::vtpm_process_get_test_result() {
    u8* fifo = state_.regs.data_fifo;
    constexpr u32 RS = sizeof(TPM2_RESPONSE_HEADER) + 2 + 4;
    RtlZeroMemory(fifo, RS);
    u8* p = fifo;
    write_response_header(p, TPM_ST_NO_SESSIONS, RS, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0);
    p += 2;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(0);
    send_response(RS);
}

void tpm::vtpm_process_pcr_read() {
    u8* fifo = state_.regs.data_fifo;
    u32 cmd_size = _byteswap_ulong(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->paramSize);
    u8* cp = fifo + sizeof(TPM2_COMMAND_HEADER);
    u32 remaining = cmd_size - sizeof(TPM2_COMMAND_HEADER);
    u32 sel_count = 0;
    u16 sel_alg = 0x000B;
    u8 sel_bytes[3] = {0x01, 0x00, 0x00};
    u8 sel_size = 3;

    if (remaining >= 4) {
        sel_count = _byteswap_ulong(*reinterpret_cast<u32*>(cp));
        cp += 4;
        remaining -= 4;

        if (sel_count >= 1 && remaining >= 3) {
            sel_alg = _byteswap_ushort(*reinterpret_cast<u16*>(cp));
            cp += 2;
            remaining -= 2;
            sel_size = *cp;
            cp += 1;
            remaining -= 1;

            if (sel_size > 3) {
                sel_size = 3;
            }

            if (remaining >= sel_size) {
                RtlCopyMemory(sel_bytes, cp, sel_size);
            }
        }
    }

    u32 digest_size = 32;
    u8* pcr_bank = nullptr;
    u32 pcr_stride = 32;

    switch (sel_alg) {
    case 0x0004:
        digest_size = 20;
        pcr_bank = &state_.pcr_sha1[0][0];
        pcr_stride = 20;
        break;
    case 0x000B:
        digest_size = 32;
        pcr_bank = &state_.pcr_sha256[0][0];
        pcr_stride = 32;
        break;
    case 0x000C:
        digest_size = 48;
        pcr_bank = &state_.pcr_sha384[0][0];
        pcr_stride = 48;
        break;
    case 0x000D:
        digest_size = 64;
        pcr_bank = &state_.pcr_sha512[0][0];
        pcr_stride = 64;
        break;
    default:
        digest_size = 32;
        pcr_bank = &state_.pcr_sha256[0][0];
        pcr_stride = 32;
        break;
    }

    const u32 selected_bit_count = static_cast<u32>(sel_size) * 8u;
    const u32 pcr_limit = static_cast<u32>(IMPLEMENTATION_PCR);
    u32 pcr_count = 0;

    for (u32 i = 0; i < selected_bit_count && i < pcr_limit; i++) {
        if (sel_bytes[i / 8] & (1 << (i % 8)))
            pcr_count++;
    }

    if (pcr_count == 0) {
        pcr_count = 1;
    }

    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 4 + 4 + 2 + 1 + 3 + 4 + pcr_count * (2 + digest_size);

    if (rs > 4096) {
        pcr_count = (4096 - sizeof(TPM2_RESPONSE_HEADER) - 4 - 4 - 2 - 1 - 3 - 4) / (2 + digest_size);
        rs = sizeof(TPM2_RESPONSE_HEADER) + 4 + 4 + 2 + 1 + 3 + 4 + pcr_count * (2 + digest_size);
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(state_.pcr_counter);
    p += 4;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(1);
    p += 4;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(sel_alg);
    p += 2;
    *p = sel_size;
    p += 1;
    RtlCopyMemory(p, sel_bytes, sel_size);
    p += 3;
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(pcr_count);
    p += 4;
    u32 written = 0;

    for (u32 i = 0; i < selected_bit_count && i < pcr_limit && written < pcr_count; i++) {
        if (sel_bytes[i / 8] & (1 << (i % 8))) {
            *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16((u16)digest_size);
            p += 2;
            RtlCopyMemory(p, pcr_bank + i * pcr_stride, digest_size);
            p += digest_size;
            written++;
        }
    }

    send_response(rs);
}

void tpm::vtpm_process_pcr_event() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);

    u32 pcr_idx = _byteswap_ulong(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    pcr_idx %= IMPLEMENTATION_PCR;

    constexpr u16 DIGEST_SIZE = 32;
    constexpr u32 DIGEST_VALUES_SIZE = 4 + 2 + DIGEST_SIZE;
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + DIGEST_VALUES_SIZE + (hs ? AR : 0);

    if (rs > sizeof(state_.regs.data_fifo)) {
        send_error(TPM_RC_FAILURE);
        return;
    }

    u8 digest[DIGEST_SIZE] = {};
    u64 seed = __rdtsc() ^ pcr_idx ^ 0x50435245ULL;
    for (u16 i = 0; i < DIGEST_SIZE; ++i) {
        digest[i] = (u8)(lcg_byte(seed) ^ state_.pcr_sha256[pcr_idx][i]);
    }
    RtlCopyMemory(state_.pcr_sha256[pcr_idx], digest, DIGEST_SIZE);
    state_.pcr_counter++;

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(DIGEST_VALUES_SIZE);
        p += 4;
    }

    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(1);
    p += 4;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(TPM_ALG_SHA256);
    p += 2;
    RtlCopyMemory(p, digest, DIGEST_SIZE);
    p += DIGEST_SIZE;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_pcr_extend() {
    u8* fifo = state_.regs.data_fifo;
    u32 pcr_idx = _byteswap_ulong(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));

    if (pcr_idx >= IMPLEMENTATION_PCR) {
        send_error(TPM_RC_VALUE);
        return;
    }

    u32 auth_size = _byteswap_ulong(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER) + 4));
    u8* dp = fifo + sizeof(TPM2_COMMAND_HEADER) + 8 + auth_size;
    u32 digest_count = _byteswap_ulong(*reinterpret_cast<u32*>(dp));
    dp += 4;

    if (digest_count == 0 || digest_count > 4) {
        send_error(TPM_RC_HASH);
        return;
    }

    for (u32 i = 0; i < digest_count; i++) {
        u16 alg = _byteswap_ushort(*reinterpret_cast<u16*>(dp));
        dp += 2;
        u8* pcr_bank = nullptr;
        u32 digest_size = 0;

        switch (alg) {
        case 0x0004:
            digest_size = 20;
            pcr_bank = state_.pcr_sha1[pcr_idx];
            break;
        case 0x000B:
            digest_size = 32;
            pcr_bank = state_.pcr_sha256[pcr_idx];
            break;
        case 0x000C:
            digest_size = 48;
            pcr_bank = state_.pcr_sha384[pcr_idx];
            break;
        case 0x000D:
            digest_size = 64;
            pcr_bank = state_.pcr_sha512[pcr_idx];
            break;
        default:
            send_error(TPM_RC_HASH);
            return;
        }

        if (!NT_SUCCESS(tpm_crypto::get()->extend_pcr_alg(alg, pcr_bank, dp, digest_size))) {
            send_error(TPM_RC_FAILURE);
            return;
        }

        dp += digest_size;
    }

    state_.pcr_counter++;
    write_response_header(fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_get_time() {
    vtpm_write_attestation_response(TPM_ST_ATTEST_TIME, TPM_CC_GetTime);
}

void tpm::vtpm_process_clear() {
    if (state_.locality != 4) {
        send_error(TPM_RC_LOCALITY);
        return;
    }

    RtlZeroMemory(&state_, sizeof(state_));
    RtlZeroMemory(state_.pcr_sha1, sizeof(state_.pcr_sha1));
    RtlZeroMemory(state_.pcr_sha256, sizeof(state_.pcr_sha256));
    RtlZeroMemory(state_.pcr_sha384, sizeof(state_.pcr_sha384));
    RtlZeroMemory(state_.pcr_sha512, sizeof(state_.pcr_sha512));
    state_.regs.access = TPM_ACCESS_VALID;
    state_.regs.sts = TPM_STS_VALID | TPM_STS_READY;
    state_.locality = 4;
    state_.pcr_counter = 1;
    write_response_header(state_.regs.data_fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_load() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);

    // handles: parentHandle (4 bytes)
    u8* params = params_after_auth(fifo, 4, hs);

    // inPrivate: TPM2B_PRIVATE (our marshaled blob), then inPublic TPM2B_PUBLIC
    u16 priv_size = big_endian_to_little_endian16(*reinterpret_cast<u16*>(params));
    const u8* blob = params + 2;
    const u8* pp = blob + priv_size;
    u16 pub_size = big_endian_to_little_endian16(*reinterpret_cast<const u16*>(pp));
    const u8* in_public = pp + 2;

    if (priv_size < 12 || pub_size < 12 || pub_size > 600 ||
        blob[0] != 'C' || blob[1] != 'B' || blob[2] != 'T' || blob[3] != '1') {
        send_error(TPM_RC_INTEGRITY);
        return;
    }

    const u8* bp = blob + 4;
    const u8* bend = blob + priv_size;
    u16 bpub = *reinterpret_cast<const u16*>(bp);
    bp += 2;
    if (bp + bpub > bend) { send_error(TPM_RC_INTEGRITY); return; }
    bp += bpub; // public copy inside the blob; the command's inPublic is authoritative
    if (bp + 2 > bend) { send_error(TPM_RC_INTEGRITY); return; }
    u16 auth_len = *reinterpret_cast<const u16*>(bp);
    bp += 2;
    if (auth_len > 64 || bp + auth_len > bend) { send_error(TPM_RC_INTEGRITY); return; }
    const u8* auth = bp;
    bp += auth_len;
    if (bp + 2 > bend) { send_error(TPM_RC_INTEGRITY); return; }
    u16 plen = *reinterpret_cast<const u16*>(bp);
    bp += 2;
    if (plen > 544 || bp + plen > bend) { send_error(TPM_RC_INTEGRITY); return; }
    const u8* priv = bp;
    bp += plen;
    if (bp >= bend) { send_error(TPM_RC_INTEGRITY); return; }
    const bool is_rsa = (*bp != 0);

    u32 new_handle = 0;
    object_slot_t* slot = alloc_slot(&new_handle);
    if (!slot) {
        send_error(TPM_RC_OBJECT_HANDLES);
        return;
    }

    slot->is_rsa = is_rsa;
    slot->public_size = pub_size;
    RtlCopyMemory(slot->public_area, in_public, pub_size);
    slot->auth_len = auth_len;
    if (auth_len)
        RtlCopyMemory(slot->auth, auth, auth_len);
    slot->priv_len = plen;
    if (plen)
        RtlCopyMemory(slot->priv, priv, plen);

    constexpr u32 AR = 2 + 32 + 1 + 2;
    constexpr u32 NM = 2 + 34;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + 4 + (hs ? 4 : 0) + NM + (hs ? AR : 0);

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);
    *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(new_handle);
    p += 4;

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(NM);
        p += 4;
    }

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(34);
    p += 2;
    p = write_computed_name(p, slot->public_area, slot->public_size);

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_unseal() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);

    u32 item_handle = big_endian_to_little_endian32(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    object_slot_t* slot = find_slot(item_handle);

    if (slot && !auth_matches(slot, fifo, 4, hs)) {
        send_error(TPM_RC_BAD_AUTH);
        return;
    }

    u16 payload = slot ? slot->priv_len : 32;
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 DS = 2 + payload;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + DS + (hs ? AR : 0);

    if (rs > 4096) {
        send_error(TPM_RC_FAILURE);
        return;
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(DS);
        p += 4;
    }

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(payload);
    p += 2;
    if (slot && payload) {
        RtlCopyMemory(p, slot->priv, payload);
    } else {
        u64 s = state_.id_seed ^ 0x554E5345414C4544ULL;
        lcg_fill(s, p, payload);
    }
    p += payload;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_sign() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);

    u32 key_handle = big_endian_to_little_endian32(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    u8* params = params_after_auth(fifo, 4, hs);
    u16 digest_len = big_endian_to_little_endian16(*reinterpret_cast<u16*>(params));
    const u8* digest = params + 2;

    object_slot_t* slot = find_slot(key_handle);

    if (slot && !auth_matches(slot, fifo, 4, hs)) {
        send_error(TPM_RC_BAD_AUTH);
        return;
    }

    u8 sig[256];
    bool have_sig = false;

    if (slot && slot->is_rsa) {
        // priv: expLen(2) + exp + n[256] + p[128] + q[128]
        const u8* pv = slot->priv;
        u16 elen = *reinterpret_cast<const u16*>(pv);
        pv += 2;
        if (elen && elen <= 4 && digest_len == 32 &&
            slot->priv_len >= (u16)(2 + elen + 256 + 128 + 128)) {
            const u8* exp = pv;
            pv += elen;
            const u8* n = pv;
            pv += 256;
            const u8* p1 = pv;
            pv += 128;
            const u8* p2 = pv;
            auto* crypto = tpm_crypto::get();
            if (crypto && NT_SUCCESS(crypto->rsa_sign_pkcs1(n, p1, p2, exp, elen, digest, sig))) {
                have_sig = true;
            } else {
                send_error(TPM_RC_FAILURE);
                return;
            }
        }
    }

    if (!have_sig) {
        // Deterministic stand-in for unknown/legacy handles and keyed-hash objects
        u64 s = state_.id_seed ^ 0x5349474E41545552ULL;
        for (u16 i = 0; i < digest_len; i++) {
            s ^= digest[i];
            s *= 0x100000001B3ULL;
        }
        lcg_fill(s, sig, sizeof(sig));
        sig[0] &= 0x7F;
    }

    constexpr u16 SIG_SIZE = 256;
    constexpr u32 TPMT_SIG = 2 + 2 + 2 + SIG_SIZE;
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + TPMT_SIG + (hs ? AR : 0);

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(TPMT_SIG);
        p += 4;
    }

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0x0014); // TPMS_SIGNATURE_RSASSA
    p += 2;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(0x000B); // SHA256
    p += 2;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(SIG_SIZE);
    p += 2;
    RtlCopyMemory(p, sig, SIG_SIZE);
    p += SIG_SIZE;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_activate_credential() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);
    constexpr u16 CERT_SIZE = 32;
    constexpr u32 DS = 2 + CERT_SIZE;
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + DS + (hs ? AR : 0);

    if (rs > 4096) {
        send_error(TPM_RC_FAILURE);
        return;
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(DS);
        p += 4;
    }

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(CERT_SIZE);
    p += 2;
    LARGE_INTEGER perf;
    KeQueryPerformanceCounter(&perf);
    u64 seed = perf.QuadPart ^ 0x4143544956435245ULL;
    lcg_fill(seed, p, CERT_SIZE);
    p += CERT_SIZE;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_make_credential() {
    u8* fifo = state_.regs.data_fifo;
    constexpr u16 CRED_SIZE = 68;
    constexpr u16 SECRET_SIZE = 256;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (2 + CRED_SIZE) + (2 + SECRET_SIZE);

    if (rs > 4096) {
        send_error(TPM_RC_FAILURE);
        return;
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);
    LARGE_INTEGER perf;
    KeQueryPerformanceCounter(&perf);
    u64 seed = perf.QuadPart ^ 0x4D414B4543524544ULL;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(CRED_SIZE);
    p += 2;
    lcg_fill(seed, p, CRED_SIZE);
    p += CRED_SIZE;
    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(SECRET_SIZE);
    p += 2;
    lcg_fill(seed, p, SECRET_SIZE);
    p += SECRET_SIZE;
    send_response(rs);
}

void tpm::vtpm_process_nv_define_space() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? AR : 0);
    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_nv_undefine_space() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);
    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? AR : 0);
    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_evict_control() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);

    // handles: auth (4) + objectHandle (4); params: persistentHandle (4)
    u32 object_handle = big_endian_to_little_endian32(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER) + 4));
    u8* params = params_after_auth(fifo, 8, hs);
    u32 persistent = big_endian_to_little_endian32(*reinterpret_cast<u32*>(params));

    object_slot_t* slot = find_slot(object_handle);
    if (slot) {
        if (object_handle == persistent) {
            free_slot(object_handle); // release from persistence
        } else {
            slot->handle = persistent; // ReadPublic/Sign now resolve via the persistent handle
        }
    }

    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? AR : 0);
    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_object_change_auth() {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    bool hs = (ctag == TPM_ST_SESSIONS);

    // handles: objectHandle (4) + parentHandle (4); params: newAuth TPM2B_AUTH
    u32 object_handle = big_endian_to_little_endian32(*reinterpret_cast<u32*>(fifo + sizeof(TPM2_COMMAND_HEADER)));
    u8* params = params_after_auth(fifo, 8, hs);
    u16 new_auth_len = big_endian_to_little_endian16(*reinterpret_cast<u16*>(params));
    const u8* new_auth = params + 2;

    object_slot_t* slot = find_slot(object_handle);

    u8 blob[1280];
    u16 blob_len;
    if (slot) {
        slot->auth_len = new_auth_len > (u16)sizeof(slot->auth) ? (u16)sizeof(slot->auth) : new_auth_len;
        if (slot->auth_len)
            RtlCopyMemory(slot->auth, new_auth, slot->auth_len);
        blob_len = marshal_blob(slot, blob);
    } else {
        blob_len = 128;
        u64 s = state_.id_seed ^ 0x4F424A4348414E47ULL;
        lcg_fill(s, blob, blob_len);
    }

    constexpr u32 AR = 2 + 32 + 1 + 2;
    u32 DS = 2 + blob_len;
    u32 rs = sizeof(TPM2_RESPONSE_HEADER) + (hs ? 4 : 0) + DS + (hs ? AR : 0);

    if (rs > 4096) {
        send_error(TPM_RC_FAILURE);
        return;
    }

    RtlZeroMemory(fifo, rs);
    u8* p = fifo;
    write_response_header(p, hs ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS, rs, TPM_RC_SUCCESS);
    p += sizeof(TPM2_RESPONSE_HEADER);

    if (hs) {
        *reinterpret_cast<u32*>(p) = big_endian_to_little_endian32(DS);
        p += 4;
    }

    *reinterpret_cast<u16*>(p) = big_endian_to_little_endian16(blob_len);
    p += 2;
    RtlCopyMemory(p, blob, blob_len);
    p += blob_len;

    if (hs) {
        write_auth_session_response(p);
    }

    send_response(rs);
}

void tpm::vtpm_process_policy_pcr() {
    write_response_header(state_.regs.data_fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_policy_command_code() {
    write_response_header(state_.regs.data_fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_policy_auth_value() {
    write_response_header(state_.regs.data_fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_policy_or() {
    write_response_header(state_.regs.data_fifo, TPM_ST_NO_SESSIONS, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}

void tpm::vtpm_process_default(u32 cmd_code) {
    u8* fifo = state_.regs.data_fifo;
    u16 ctag = big_endian_to_little_endian16(reinterpret_cast<TPM2_COMMAND_HEADER*>(fifo)->tag);
    debug::log_info("TPM MMIO: Unhandled command 0x%08X\n", cmd_code);
    write_response_header(fifo, ctag, sizeof(TPM2_RESPONSE_HEADER), TPM_RC_SUCCESS);
    send_response(sizeof(TPM2_RESPONSE_HEADER));
}
}
