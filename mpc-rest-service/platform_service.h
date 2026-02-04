#pragma once

#include "cosigner/platform_service.h"
#include <string>
#include <cstdint>

using namespace fireblocks::common::cosigner;

class simple_platform_service : public platform_service {
public:
    simple_platform_service(uint64_t player_id) : _player_id(player_id) {}
    virtual ~simple_platform_service() = default;

    void gen_random(size_t len, uint8_t* random_data) const override;
    const std::string get_current_tenantid() const override;
    uint64_t get_id_from_keyid(const std::string& key_id) const override;
    void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override;
    byte_vector_t encrypt_for_player(uint64_t id, const byte_vector_t& data) const override;
    byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const override;
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) override;
    void on_start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const signing_type signature_type) override;
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override;
    bool is_client_id(uint64_t player_id) const override;
    uint64_t now_msec() const override;

private:
    uint64_t _player_id;
};
