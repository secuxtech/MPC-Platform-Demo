#include "json_utils.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string length");
    }

    std::vector<uint8_t> result;
    result.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        result.push_back(byte);
    }

    return result;
}

cosigner_sign_algorithm parse_algorithm(const std::string& algo) {
    if (algo == "ECDSA_SECP256K1") return ECDSA_SECP256K1;
    if (algo == "ECDSA_SECP256R1") return ECDSA_SECP256R1;
    if (algo == "EDDSA_ED25519") return EDDSA_ED25519;
    if (algo == "ECDSA_STARK") return ECDSA_STARK;
    throw std::invalid_argument("Unknown algorithm: " + algo);
}

std::string algorithm_to_string(cosigner_sign_algorithm algo) {
    switch (algo) {
        case ECDSA_SECP256K1: return "ECDSA_SECP256K1";
        case ECDSA_SECP256R1: return "ECDSA_SECP256R1";
        case EDDSA_ED25519: return "EDDSA_ED25519";
        case ECDSA_STARK: return "ECDSA_STARK";
        default: return "UNKNOWN";
    }
}
