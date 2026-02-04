#include "persistency.h"
#include "cosigner/cosigner_exception.h"
#include <cstring>

bool simple_persistency::key_exist(const std::string& key_id) const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _keys.find(key_id) != _keys.end();
}

void simple_persistency::load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end()) {
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }
    algorithm = it->second.algorithm;
    memcpy(&private_key, &it->second.private_key, sizeof(elliptic_curve256_scalar_t));
}

const std::string simple_persistency::get_tenantid_from_keyid(const std::string& key_id) const {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end()) {
        return "";
    }
    return it->second.tenant_id;
}

void simple_persistency::load_key_metadata(const std::string& key_id, cmp_key_metadata& metadata, bool full_load) const {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end()) {
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }
    metadata = it->second.metadata;
}

void simple_persistency::load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end()) {
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }
    aux = it->second.aux;
}

void simple_persistency::store_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl) {
    std::lock_guard<std::mutex> lock(_mutex);
    auto& data = _keys[key_id];
    data.algorithm = algorithm;
    memcpy(&data.private_key, &private_key, sizeof(elliptic_curve256_scalar_t));
}

void simple_persistency::store_key_metadata(const std::string& key_id, const cmp_key_metadata& metadata, bool allow_override) {
    std::lock_guard<std::mutex> lock(_mutex);
    _keys[key_id].metadata = metadata;
}

void simple_persistency::store_auxiliary_keys(const std::string& key_id, const auxiliary_keys& aux) {
    std::lock_guard<std::mutex> lock(_mutex);
    _keys[key_id].aux = aux;
}

void simple_persistency::store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) {
    std::lock_guard<std::mutex> lock(_mutex);
    _keys[key_id].tenant_id = tenant_id;
}

void simple_persistency::store_setup_data(const std::string& key_id, const setup_data& metadata) {
    std::lock_guard<std::mutex> lock(_mutex);
    _keys[key_id].setup = metadata;
}

void simple_persistency::load_setup_data(const std::string& key_id, setup_data& metadata) {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end()) {
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }
    metadata = it->second.setup;
}

void simple_persistency::store_setup_commitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments) {
    std::lock_guard<std::mutex> lock(_mutex);
    _keys[key_id].commitments = commitments;
}

void simple_persistency::load_setup_commitments(const std::string& key_id, std::map<uint64_t, commitment>& commitments) {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end()) {
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }
    commitments = it->second.commitments;
}

void simple_persistency::delete_temporary_key_data(const std::string& key_id, bool delete_key) {
    std::lock_guard<std::mutex> lock(_mutex);
    if (delete_key) {
        _keys.erase(key_id);
    }
}

void simple_persistency::store_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) {
    std::lock_guard<std::mutex> lock(_mutex);
    _signing_data[txid] = data;
}

void simple_persistency::load_cmp_signing_data(const std::string& txid, cmp_signing_metadata& data) const {
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _signing_data.find(txid);
    if (it == _signing_data.end()) {
        throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    }
    data = it->second;
}

void simple_persistency::update_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) {
    std::lock_guard<std::mutex> lock(_mutex);
    _signing_data[txid] = data;
}

void simple_persistency::delete_temporary_signing_data(const std::string& txid) {
    std::lock_guard<std::mutex> lock(_mutex);
    _signing_data.erase(txid);
}
