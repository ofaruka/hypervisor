#pragma once
#include "../includes.h"
#include "includes/tpm20.h"

namespace svm {

class tpm {
  public:
    static constexpr u8 EK_AUTH_POLICY[32] = {0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
                                              0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
                                              0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA};
    struct registers_t {
        u8 access;
        u32 sts;
        u32 interface_id;
        u32 interface_capability;
        u32 did_vid;
        u8 rid;
        u32 burst_count;
        u8 data_fifo[4096];
        u32 response_size;
    };
    struct nv_entry_t {
        bool defined;
        u32 index;
        u32 attributes;
        u32 size;
        u8 data[MAX_NV_SIZE];
    };
    // A guest-created key/sealed object (NGC / Hello PIN keys). The private
    // blob handed to the guest is our own marshaled copy of this slot, so the
    // object survives reboots inside the caller-persisted blob (NGC container)
    // as long as the SRK/EK identity stays stable across boots.
    struct object_slot_t {
        bool used;
        u32 handle;
        bool is_rsa;
        u16 public_size;
        u8 public_area[600];
        u16 auth_len;
        u8 auth[64];
        u16 priv_len;
        u8 priv[544]; // RSA: u16 exp_len + exp + n[256] + p[128] + q[128]; sealed: payload
    };
    struct state_t {
        registers_t regs;
        u8 locality;
        bool expect_data;
        u32 fifo_index;
        u8 pcr_sha1[IMPLEMENTATION_PCR][20];
        u8 pcr_sha256[IMPLEMENTATION_PCR][32];
        u8 pcr_sha384[IMPLEMENTATION_PCR][48];
        u8 pcr_sha512[IMPLEMENTATION_PCR][64];
        u32 pcr_counter;
        u32 supported_banks;
        nv_entry_t nv[MAX_NV_INDICES];
        u32 nv_count;
        u8 ek_pub[512];
        u32 ek_pub_size;
        u8 ek_cert_der[2048];
        u32 ek_cert_der_size;
        bool ek_cert_generated;
        u64 id_seed;
        object_slot_t objects[8];
    };
    tpm() = default;
    static tpm* get();
    void initialize();
    bool is_tpm_address(u64 pa);
    u64 handle_read(u64 pa, u32 offset, u32 size);
    void handle_write(u64 pa, u32 offset, u64 value, u32 size);
    const u8* get_ek_public() const {
        return state_.ek_pub;
    }
    u32 get_ek_public_size() const {
        return state_.ek_pub_size;
    }
    struct pcr_all_banks {
        u8 sha1[IMPLEMENTATION_PCR][20];
        u8 sha256[IMPLEMENTATION_PCR][32];
        u8 sha384[IMPLEMENTATION_PCR][48];
        u8 sha512[IMPLEMENTATION_PCR][64];
        u32 supported_banks;
    };
    void set_pcr_values(const pcr_all_banks& banks);
    void set_identity_seed(u64 seed);

  private:
    void initialize_pcrs();
    u32 big_endian_to_little_endian32(u32 value);
    u16 big_endian_to_little_endian16(u16 value);
    void write_response_header(u8* buf, u16 tag, u32 size, u32 response_code);
    void send_error(TPM_RC code);
    void send_response(u32 size);
    u32 write_auth_session_response(u8* ptr);
    void copy_rsa_modulus(u8* dest, u16 max_size);
    u8* write_ek_rsa_public(u8* ptr);
    u8* write_srk_rsa_public(u8* ptr);
    u8 lcg_byte(u64& seed);
    void lcg_fill(u64& seed, u8* buf, u32 len);
    void process_command();
    TPM_RC validate_size();
    TPM_RC validate_locality();
    void vtpm_process_startup();
    void vtpm_process_self_test();
    void vtpm_process_get_capability();
    void vtpm_process_get_random();
    void vtpm_process_read_public();
    void vtpm_process_nv_read_public();
    void vtpm_process_nv_read();
    void vtpm_process_nv_write();
    void vtpm_process_rsa_encrypt();
    void vtpm_process_hash_sequence_start();
    void vtpm_process_hash();
    void vtpm_process_certify_creation();
    void vtpm_process_certify();
    void vtpm_process_quote();
    void vtpm_process_verify_signature();
    void vtpm_process_create();
    void vtpm_process_create_primary();
    void vtpm_process_start_auth_session();
    void vtpm_process_flush_context();
    void vtpm_process_read_clock();
    void vtpm_process_policy_secret();
    void vtpm_process_policy_get_digest();
    void vtpm_process_get_test_result();
    void vtpm_process_pcr_read();
    void vtpm_process_pcr_event();
    void vtpm_process_pcr_extend();
    void vtpm_process_get_time();
    void vtpm_process_clear();
    void vtpm_process_load();
    void vtpm_process_unseal();
    void vtpm_process_sign();
    void vtpm_process_activate_credential();
    void vtpm_process_make_credential();
    void vtpm_process_nv_define_space();
    void vtpm_process_nv_undefine_space();
    void vtpm_process_evict_control();
    void vtpm_process_object_change_auth();
    void vtpm_process_policy_pcr();
    void vtpm_process_policy_command_code();
    void vtpm_process_policy_auth_value();
    void vtpm_process_policy_or();
    void vtpm_process_default(u32 cmd_code);
    void vtpm_write_attestation_response(u16 attestation_type, u32 salt);
    nv_entry_t* find_nv_index(u32 index);
    nv_entry_t* create_nv_index(u32 index, u32 attributes, u32 size);
    // Persistent identity + NGC-grade object handling
    void seed_identity();
    void derive_ek_public();
    void compute_name(const u8* public_area, u32 public_size, u8* out34);
    u8* write_computed_name(u8* ptr, const u8* public_area, u32 public_size);
    u8* params_after_auth(u8* cmd, u32 handles_size, bool has_sessions);
    bool read_pw_auth(u8* cmd, u32 handles_size, bool has_sessions, u8* auth, u16* auth_len);
    bool auth_matches(const object_slot_t* slot, u8* cmd, u32 handles_size, bool has_sessions);
    object_slot_t* alloc_slot(u32* handle_out);
    object_slot_t* find_slot(u32 handle);
    void free_slot(u32 handle);
    u16 marshal_blob(const object_slot_t* slot, u8* out);
    state_t state_;
    KSPIN_LOCK lock_;
};
}
