#pragma once

#include <nlohmann/json.hpp>
#include <memory>
#include "cosigner/cmp_setup_service.h"
#include "cosigner/cmp_ecdsa_online_signing_service.h"
#include "platform_service.h"
#include "persistency.h"

using json = nlohmann::json;
using namespace fireblocks::common::cosigner;

class MPCWrapper {
public:
    MPCWrapper(uint64_t player_id);
    ~MPCWrapper() = default;

    // Setup APIs
    json generate_setup_commitments(const json& input);
    json store_setup_commitments(const json& input);
    json generate_setup_proofs(const json& input);
    json verify_setup_proofs(const json& input);
    json create_secret(const json& input);

    // Signing APIs
    json start_signing(const json& input);
    json mta_response(const json& input);
    json mta_verify(const json& input);
    json get_si(const json& input);
    json get_signature(const json& input);

private:
    uint64_t _player_id;
    simple_platform_service _platform_service;
    simple_persistency _persistency;
    std::unique_ptr<cmp_setup_service> _setup_service;
    std::unique_ptr<cmp_ecdsa_online_signing_service> _signing_service;
};
