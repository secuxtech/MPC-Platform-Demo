#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include "httplib.h"
#include "mpc_wrapper.h"

using json = nlohmann::json;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <port> <player_id>" << std::endl;
        return 1;
    }

    int port = std::atoi(argv[1]);
    uint64_t player_id = std::stoull(argv[2]);

    std::cout << "Starting MPC REST Service..." << std::endl;
    std::cout << "Port: " << port << std::endl;
    std::cout << "Player ID: " << player_id << std::endl;

    // Create MPC wrapper
    auto mpc_wrapper = std::make_unique<MPCWrapper>(player_id);

    // Create HTTP server
    httplib::Server svr;

    // Helper to handle API requests
    auto handle_api = [&](const httplib::Request& req, httplib::Response& res,
                          const std::function<json(const json&)>& handler) {
        try {
            json input = json::parse(req.body);
            json output = handler(input);
            res.set_content(output.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            json error = {{"error", e.what()}};
            res.set_content(error.dump(), "application/json");
        }
    };

    // Setup APIs
    svr.Post("/generate_setup_commitments", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->generate_setup_commitments(input);
        });
    });

    svr.Post("/store_setup_commitments", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->store_setup_commitments(input);
        });
    });

    svr.Post("/generate_setup_proofs", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->generate_setup_proofs(input);
        });
    });

    svr.Post("/verify_setup_proofs", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->verify_setup_proofs(input);
        });
    });

    svr.Post("/create_secret", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->create_secret(input);
        });
    });

    // Signing APIs
    svr.Post("/start_signing", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->start_signing(input);
        });
    });

    svr.Post("/mta_response", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->mta_response(input);
        });
    });

    svr.Post("/mta_verify", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->mta_verify(input);
        });
    });

    svr.Post("/get_si", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->get_si(input);
        });
    });

    svr.Post("/get_signature", [&](const httplib::Request& req, httplib::Response& res) {
        handle_api(req, res, [&](const json& input) {
            return mpc_wrapper->get_signature(input);
        });
    });

    // Health check endpoint
    svr.Get("/health", [&](const httplib::Request& req, httplib::Response& res) {
        json response = {
            {"status", "ok"},
            {"playerId", player_id}
        };
        res.set_content(response.dump(), "application/json");
    });

    std::cout << "Server starting on port " << port << "..." << std::endl;
    std::cout << "Available endpoints:" << std::endl;
    std::cout << "  POST /generate_setup_commitments" << std::endl;
    std::cout << "  POST /store_setup_commitments" << std::endl;
    std::cout << "  POST /generate_setup_proofs" << std::endl;
    std::cout << "  POST /verify_setup_proofs" << std::endl;
    std::cout << "  POST /create_secret" << std::endl;
    std::cout << "  POST /start_signing" << std::endl;
    std::cout << "  POST /mta_response" << std::endl;
    std::cout << "  POST /mta_verify" << std::endl;
    std::cout << "  POST /get_si" << std::endl;
    std::cout << "  POST /get_signature" << std::endl;
    std::cout << "  GET  /health" << std::endl;

    if (!svr.listen("0.0.0.0", port)) {
        std::cerr << "Failed to start server on port " << port << std::endl;
        return 1;
    }

    return 0;
}
