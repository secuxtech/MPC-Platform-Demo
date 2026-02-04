#include "platform_service.h"
#include <openssl/rand.h>
#include <chrono>
#include <stdexcept>

void simple_platform_service::gen_random(size_t len, uint8_t* random_data) const {
    if (RAND_bytes(random_data, len) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
}

const std::string simple_platform_service::get_current_tenantid() const {
    return "test-tenant";
}

uint64_t simple_platform_service::get_id_from_keyid(const std::string& key_id) const {
    return _player_id;
}

void simple_platform_service::derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const {
    // Not used in online signing - leave empty
}

byte_vector_t simple_platform_service::encrypt_for_player(uint64_t id, const byte_vector_t& data) const {
    // Simple implementation - no encryption for now
    return data;
}

byte_vector_t simple_platform_service::decrypt_message(const byte_vector_t& encrypted_data) const {
    // Simple implementation - no decryption for now
    return encrypted_data;
}

bool simple_platform_service::backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) {
    // Always allow key backup
    return true;
}

void simple_platform_service::on_start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const signing_type signature_type) {
    // No validation - coordinator handles this
}

void simple_platform_service::fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const {
    // Default flags
    flags.push_back(0);
}

bool simple_platform_service::is_client_id(uint64_t player_id) const {
    return false;
}

uint64_t simple_platform_service::now_msec() const {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}
