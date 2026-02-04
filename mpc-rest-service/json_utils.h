#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "cosigner/sign_algorithm.h"

using json = nlohmann::json;

// Convert binary data to hex string
std::string to_hex(const uint8_t* data, size_t len);

// Convert hex string to binary data
std::vector<uint8_t> from_hex(const std::string& hex);

// Parse algorithm string to enum
cosigner_sign_algorithm parse_algorithm(const std::string& algo);

// Convert algorithm enum to string
std::string algorithm_to_string(cosigner_sign_algorithm algo);
