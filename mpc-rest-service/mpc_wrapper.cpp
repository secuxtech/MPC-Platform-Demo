#include "mpc_wrapper.h"
#include "json_utils.h"
#include "cosigner/types.h"
#include <stdexcept>

using namespace fireblocks::common::cosigner;

MPCWrapper::MPCWrapper(uint64_t player_id)
    : _player_id(player_id),
      _platform_service(player_id),
      _persistency() {
    _setup_service = std::make_unique<cmp_setup_service>(_platform_service, _persistency);
    _signing_service = std::make_unique<cmp_ecdsa_online_signing_service>(_platform_service, _persistency, _persistency);
}

// Helpers - arrays not structs!
json point_to_json(const elliptic_curve_point& point) {
    return to_hex(point.data, sizeof(point.data));
}

json scalar_to_json(const elliptic_curve_scalar& scalar) {
    return to_hex(scalar.data, sizeof(scalar.data));
}

json commitment_to_json(const commitment& comm) {
    // Serialize both salt and commitment (64 bytes total)
    return to_hex(reinterpret_cast<const uint8_t*>(&comm.data), sizeof(comm.data));
}

commitment json_to_commitment(const std::string& hex) {
    auto bytes = from_hex(hex);
    commitment comm;
    if (bytes.size() != sizeof(comm.data)) {
        throw std::invalid_argument("Invalid commitment size");
    }
    memcpy(&comm.data, bytes.data(), bytes.size());
    return comm;
}

elliptic_curve_scalar json_to_scalar(const std::string& hex) {
    auto bytes = from_hex(hex);
    elliptic_curve_scalar scalar;
    if (bytes.size() != sizeof(scalar.data)) {
        throw std::invalid_argument("Invalid scalar size");
    }
    memcpy(scalar.data, bytes.data(), bytes.size());
    return scalar;
}

json MPCWrapper::generate_setup_commitments(const json& input) {
    std::string key_id = input["keyId"];
    std::string tenant_id = input["tenantId"];
    std::string algorithm = input["algorithm"];
    std::vector<uint64_t> players_ids = input["playerIds"].get<std::vector<uint64_t>>();
    uint8_t threshold = input["threshold"];

    commitment setup_commitment;
    share_derivation_args derive_from;

    _setup_service->generate_setup_commitments(
        key_id, tenant_id, parse_algorithm(algorithm),
        players_ids, threshold, 0, derive_from, setup_commitment
    );

    json result;
    result["commitment"] = commitment_to_json(setup_commitment);
    return result;
}

json MPCWrapper::store_setup_commitments(const json& input) {
    std::string key_id = input["keyId"];
    std::string tenant_id = input.value("tenantId", "test-tenant");

    // Store tenant_id for this key before calling mpc-lib
    // This is needed because each player needs to know the tenant for validation
    _persistency.store_keyid_tenant_id(key_id, tenant_id);

    std::map<uint64_t, commitment> commitments;
    for (const auto& item : input["commitments"]) {
        uint64_t player_id = item["playerId"];
        commitments[player_id] = json_to_commitment(item["commitment"]);
    }

    setup_decommitment decommitment;
    _setup_service->store_setup_commitments(key_id, commitments, decommitment);

    json result;
    result["ack"] = to_hex(decommitment.ack, sizeof(decommitment.ack));
    result["seed"] = to_hex(decommitment.seed, sizeof(decommitment.seed));
    result["share"] = {
        {"X", point_to_json(decommitment.share.X)},
        {"schnorr_R", point_to_json(decommitment.share.schnorr_R)}
    };
    result["paillierPublicKey"] = to_hex(decommitment.paillier_public_key.data(), decommitment.paillier_public_key.size());
    result["ringPedersenPublicKey"] = to_hex(decommitment.ring_pedersen_public_key.data(), decommitment.ring_pedersen_public_key.size());

    return result;
}

json MPCWrapper::generate_setup_proofs(const json& input) {
    std::string key_id = input["keyId"];

    std::map<uint64_t, setup_decommitment> decommitments;
    for (const auto& item : input["decommitments"]) {
        uint64_t player_id = item["playerId"];
        setup_decommitment decomm;

        auto ack_bytes = from_hex(item["ack"].get<std::string>());
        memcpy(decomm.ack, ack_bytes.data(), sizeof(decomm.ack));

        auto seed_bytes = from_hex(item["seed"].get<std::string>());
        memcpy(decomm.seed, seed_bytes.data(), sizeof(decomm.seed));

        auto x_bytes = from_hex(item["share"]["X"].get<std::string>());
        memcpy(decomm.share.X.data, x_bytes.data(), sizeof(decomm.share.X.data));

        auto r_bytes = from_hex(item["share"]["schnorr_R"].get<std::string>());
        memcpy(decomm.share.schnorr_R.data, r_bytes.data(), sizeof(decomm.share.schnorr_R.data));

        decomm.paillier_public_key = from_hex(item["paillierPublicKey"].get<std::string>());
        decomm.ring_pedersen_public_key = from_hex(item["ringPedersenPublicKey"].get<std::string>());

        decommitments[player_id] = decomm;
    }

    setup_zk_proofs proofs;
    _setup_service->generate_setup_proofs(key_id, decommitments, proofs);

    json result;
    result["schnorr_s"] = scalar_to_json(proofs.schnorr_s);
    result["paillierBlumZkp"] = to_hex(proofs.paillier_blum_zkp.data(), proofs.paillier_blum_zkp.size());
    result["ringPedersenParamZkp"] = to_hex(proofs.ring_pedersen_param_zkp.data(), proofs.ring_pedersen_param_zkp.size());

    return result;
}

json MPCWrapper::verify_setup_proofs(const json& input) {
    std::string key_id = input["keyId"];

    std::map<uint64_t, setup_zk_proofs> proofs;
    for (const auto& item : input["proofs"]) {
        uint64_t player_id = item["playerId"];
        setup_zk_proofs proof;

        proof.schnorr_s = json_to_scalar(item["schnorr_s"].get<std::string>());
        proof.paillier_blum_zkp = from_hex(item["paillierBlumZkp"].get<std::string>());
        proof.ring_pedersen_param_zkp = from_hex(item["ringPedersenParamZkp"].get<std::string>());

        proofs[player_id] = proof;
    }

    std::map<uint64_t, byte_vector_t> paillier_large_factor_proofs;
    _setup_service->verify_setup_proofs(key_id, proofs, paillier_large_factor_proofs);

    json result;
    json proofs_array = json::array();
    for (const auto& [player_id, proof] : paillier_large_factor_proofs) {
        proofs_array.push_back({
            {"playerId", player_id},
            {"proof", to_hex(proof.data(), proof.size())}
        });
    }
    result["paillierLargeFactorProofs"] = proofs_array;

    return result;
}

json MPCWrapper::create_secret(const json& input) {
    std::string key_id = input["keyId"];

    std::map<uint64_t, std::map<uint64_t, byte_vector_t>> paillier_large_factor_proofs;
    for (const auto& player_item : input["paillierLargeFactorProofs"]) {
        uint64_t from_player_id = player_item["fromPlayerId"];
        for (const auto& proof_item : player_item["proofs"]) {
            uint64_t to_player_id = proof_item["playerId"];
            paillier_large_factor_proofs[from_player_id][to_player_id] = from_hex(proof_item["proof"].get<std::string>());
        }
    }

    std::string public_key;
    cosigner_sign_algorithm algorithm;
    _setup_service->create_secret(key_id, paillier_large_factor_proofs, public_key, algorithm);

    json result;
    result["publicKey"] = to_hex(reinterpret_cast<const uint8_t*>(public_key.data()), public_key.size());
    result["algorithm"] = algorithm_to_string(algorithm);

    return result;
}

json MPCWrapper::start_signing(const json& input) {
    std::string key_id = input["keyId"];
    std::string txid = input["txid"];
    cosigner_sign_algorithm algorithm = parse_algorithm(input["algorithm"].get<std::string>());

    signing_data data;
    if (input.contains("chaincode")) {
        auto chaincode_bytes = from_hex(input["chaincode"].get<std::string>());
        memcpy(data.chaincode, chaincode_bytes.data(), std::min(chaincode_bytes.size(), sizeof(HDChaincode)));
    } else {
        memset(data.chaincode, 0, sizeof(HDChaincode));
    }

    for (const auto& block : input["blocks"]) {
        signing_block_data block_data;
        block_data.data = from_hex(block["data"].get<std::string>());
        if (block.contains("path")) {
            block_data.path = block["path"].get<std::vector<uint32_t>>();
        }
        data.blocks.push_back(block_data);
    }

    std::string metadata_json = input.value("metadata", "{}");
    std::set<std::string> players = input["players"].get<std::set<std::string>>();
    std::set<uint64_t> players_ids = input["playerIds"].get<std::set<uint64_t>>();

    std::vector<cmp_mta_request> mta_requests;
    _signing_service->start_signing(key_id, txid, algorithm, data, metadata_json, players, players_ids, mta_requests);

    json result;
    json mta_array = json::array();
    for (const auto& req : mta_requests) {
        json req_json;
        req_json["K"] = to_hex(req.mta.message.data(), req.mta.message.size());
        req_json["G"] = to_hex(req.mta.commitment.data(), req.mta.commitment.size());
        req_json["c_key"] = to_hex(req.mta.proof.data(), req.mta.proof.size());

        json proofs = json::object();
        for (const auto& [player_id, proof] : req.mta_proofs) {
            proofs[std::to_string(player_id)] = to_hex(proof.data(), proof.size());
        }
        req_json["mta_proofs"] = proofs;

        req_json["A"] = point_to_json(req.A);
        req_json["B"] = point_to_json(req.B);
        req_json["Z"] = point_to_json(req.Z);

        mta_array.push_back(req_json);
    }
    result["mtaRequests"] = mta_array;
    return result;
}

json MPCWrapper::mta_response(const json& input) {
    std::string txid = input["txid"];
    uint32_t version = input.value("version", 0);

    std::map<uint64_t, std::vector<cmp_mta_request>> requests;
    for (const auto& player_req : input["requests"]) {
        uint64_t player_id = player_req["playerId"];
        std::vector<cmp_mta_request> player_requests;

        for (const auto& req_json : player_req["mtaRequests"]) {
            cmp_mta_request req;
            req.mta.message = from_hex(req_json["K"].get<std::string>());
            req.mta.commitment = from_hex(req_json["G"].get<std::string>());
            req.mta.proof = from_hex(req_json["c_key"].get<std::string>());

            for (const auto& [key, val] : req_json["mta_proofs"].items()) {
                req.mta_proofs[std::stoull(key)] = from_hex(val.get<std::string>());
            }

            auto a_bytes = from_hex(req_json["A"].get<std::string>());
            memcpy(req.A.data, a_bytes.data(), sizeof(req.A.data));
            auto b_bytes = from_hex(req_json["B"].get<std::string>());
            memcpy(req.B.data, b_bytes.data(), sizeof(req.B.data));
            auto z_bytes = from_hex(req_json["Z"].get<std::string>());
            memcpy(req.Z.data, z_bytes.data(), sizeof(req.Z.data));

            player_requests.push_back(req);
        }
        requests[player_id] = player_requests;
    }

    cmp_mta_responses response;
    uint64_t flags = _signing_service->mta_response(txid, requests, version, response);

    json result;
    result["flags"] = flags;
    result["ack"] = to_hex(response.ack, sizeof(response.ack));

    json resp_array = json::array();
    for (const auto& resp : response.response) {
        json resp_json;

        json k_gamma_mta = json::object();
        for (const auto& [pid, msg] : resp.k_gamma_mta) {
            json msg_json;
            msg_json["K_"] = to_hex(msg.message.data(), msg.message.size());
            msg_json["G_"] = to_hex(msg.commitment.data(), msg.commitment.size());
            msg_json["c_k_w"] = to_hex(msg.proof.data(), msg.proof.size());
            k_gamma_mta[std::to_string(pid)] = msg_json;
        }
        resp_json["k_gamma_mta"] = k_gamma_mta;

        json k_x_mta = json::object();
        for (const auto& [pid, msg] : resp.k_x_mta) {
            json msg_json;
            msg_json["K_"] = to_hex(msg.message.data(), msg.message.size());
            msg_json["G_"] = to_hex(msg.commitment.data(), msg.commitment.size());
            msg_json["c_k_w"] = to_hex(msg.proof.data(), msg.proof.size());
            k_x_mta[std::to_string(pid)] = msg_json;
        }
        resp_json["k_x_mta"] = k_x_mta;

        resp_json["GAMMA"] = point_to_json(resp.GAMMA);

        json gamma_proofs = json::object();
        for (const auto& [pid, proof] : resp.gamma_proofs) {
            gamma_proofs[std::to_string(pid)] = to_hex(proof.data(), proof.size());
        }
        resp_json["gamma_proofs"] = gamma_proofs;

        resp_array.push_back(resp_json);
    }
    result["responses"] = resp_array;
    return result;
}

json MPCWrapper::mta_verify(const json& input) {
    std::string txid = input["txid"];

    std::map<uint64_t, cmp_mta_responses> mta_responses;
    for (const auto& player_resp : input["mtaResponses"]) {
        uint64_t player_id = player_resp["playerId"];
        cmp_mta_responses resp;

        auto ack_bytes = from_hex(player_resp["ack"].get<std::string>());
        memcpy(resp.ack, ack_bytes.data(), sizeof(resp.ack));

        for (const auto& resp_json : player_resp["responses"]) {
            cmp_mta_response r;

            for (const auto& [key, val] : resp_json["k_gamma_mta"].items()) {
                uint64_t pid = std::stoull(key);
                cmp_mta_message msg;
                msg.message = from_hex(val["K_"].get<std::string>());
                msg.commitment = from_hex(val["G_"].get<std::string>());
                msg.proof = from_hex(val["c_k_w"].get<std::string>());
                r.k_gamma_mta[pid] = msg;
            }

            for (const auto& [key, val] : resp_json["k_x_mta"].items()) {
                uint64_t pid = std::stoull(key);
                cmp_mta_message msg;
                msg.message = from_hex(val["K_"].get<std::string>());
                msg.commitment = from_hex(val["G_"].get<std::string>());
                msg.proof = from_hex(val["c_k_w"].get<std::string>());
                r.k_x_mta[pid] = msg;
            }

            auto gamma_bytes = from_hex(resp_json["GAMMA"].get<std::string>());
            memcpy(r.GAMMA.data, gamma_bytes.data(), sizeof(r.GAMMA.data));

            for (const auto& [key, val] : resp_json["gamma_proofs"].items()) {
                r.gamma_proofs[std::stoull(key)] = from_hex(val.get<std::string>());
            }

            resp.response.push_back(r);
        }
        mta_responses[player_id] = resp;
    }

    std::vector<cmp_mta_deltas> deltas;
    uint64_t flags = _signing_service->mta_verify(txid, mta_responses, deltas);

    json result;
    result["flags"] = flags;
    json deltas_array = json::array();
    for (const auto& delta : deltas) {
        json delta_json;
        delta_json["delta"] = scalar_to_json(delta.delta);
        delta_json["DELTA"] = point_to_json(delta.DELTA);
        delta_json["proof"] = to_hex(delta.proof.data(), delta.proof.size());
        deltas_array.push_back(delta_json);
    }
    result["deltas"] = deltas_array;
    return result;
}

json MPCWrapper::get_si(const json& input) {
    std::string txid = input["txid"];

    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
    for (const auto& player_delta : input["deltas"]) {
        uint64_t player_id = player_delta["playerId"];
        std::vector<cmp_mta_deltas> player_deltas;

        for (const auto& delta_json : player_delta["deltas"]) {
            cmp_mta_deltas delta;
            delta.delta = json_to_scalar(delta_json["delta"].get<std::string>());

            auto delta_bytes = from_hex(delta_json["DELTA"].get<std::string>());
            memcpy(delta.DELTA.data, delta_bytes.data(), sizeof(delta.DELTA.data));

            delta.proof = from_hex(delta_json["proof"].get<std::string>());

            player_deltas.push_back(delta);
        }
        deltas[player_id] = player_deltas;
    }

    std::vector<elliptic_curve_scalar> sis;
    uint64_t flags = _signing_service->get_si(txid, deltas, sis);

    json result;
    result["flags"] = flags;
    json sis_array = json::array();
    for (const auto& si : sis) {
        sis_array.push_back(scalar_to_json(si));
    }
    result["sis"] = sis_array;
    return result;
}

json MPCWrapper::get_signature(const json& input) {
    std::string txid = input["txid"];

    std::map<uint64_t, std::vector<elliptic_curve_scalar>> s_values;
    for (const auto& player_s : input["s"]) {
        uint64_t player_id = player_s["playerId"];
        std::vector<elliptic_curve_scalar> player_sis;

        for (const auto& si_hex : player_s["sis"]) {
            player_sis.push_back(json_to_scalar(si_hex.get<std::string>()));
        }
        s_values[player_id] = player_sis;
    }

    std::vector<recoverable_signature> full_sig;
    uint64_t flags = _signing_service->get_cmp_signature(txid, s_values, full_sig);

    json result;
    result["flags"] = flags;
    json sigs_array = json::array();
    for (const auto& sig : full_sig) {
        json sig_json;
        sig_json["r"] = to_hex(sig.r, sizeof(sig.r));
        sig_json["s"] = to_hex(sig.s, sizeof(sig.s));
        sig_json["v"] = sig.v;
        sigs_array.push_back(sig_json);
    }
    result["signatures"] = sigs_array;
    return result;
}
