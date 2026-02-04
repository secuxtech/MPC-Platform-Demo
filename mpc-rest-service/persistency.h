#pragma once

#include "cosigner/cmp_setup_service.h"
#include "cosigner/cmp_ecdsa_online_signing_service.h"
#include <map>
#include <string>
#include <mutex>

using namespace fireblocks::common::cosigner;

// In-memory persistency for setup service
class simple_persistency :
    public cmp_setup_service::setup_key_persistency,
    public cmp_ecdsa_online_signing_service::signing_persistency {
public:
    virtual ~simple_persistency() = default;

    // cmp_key_persistency methods
    bool key_exist(const std::string& key_id) const override;
    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override;
    const std::string get_tenantid_from_keyid(const std::string& key_id) const override;
    void load_key_metadata(const std::string& key_id, cmp_key_metadata& metadata, bool full_load) const override;
    void load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const override;

    // setup_key_persistency methods
    void store_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl = 0) override;
    void store_key_metadata(const std::string& key_id, const cmp_key_metadata& metadata, bool allow_override) override;
    void store_auxiliary_keys(const std::string& key_id, const auxiliary_keys& aux) override;
    void store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) override;
    void store_setup_data(const std::string& key_id, const setup_data& metadata) override;
    void load_setup_data(const std::string& key_id, setup_data& metadata) override;
    void store_setup_commitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments) override;
    void load_setup_commitments(const std::string& key_id, std::map<uint64_t, commitment>& commitments) override;
    void delete_temporary_key_data(const std::string& key_id, bool delete_key = false) override;

    // signing_persistency methods
    void store_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) override;
    void load_cmp_signing_data(const std::string& txid, cmp_signing_metadata& data) const override;
    void update_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) override;
    void delete_temporary_signing_data(const std::string& txid) override;

private:
    struct key_data {
        cosigner_sign_algorithm algorithm;
        elliptic_curve256_scalar_t private_key;
        std::string tenant_id;
        cmp_key_metadata metadata;
        auxiliary_keys aux;
        setup_data setup;
        std::map<uint64_t, commitment> commitments;
    };

    mutable std::mutex _mutex;
    std::map<std::string, key_data> _keys;
    std::map<std::string, cmp_signing_metadata> _signing_data;
};
