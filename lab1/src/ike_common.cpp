#include "ike_common.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <random>
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::vector<uint8_t> generate_random_data(size_t size, uint32_t seed) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    std::vector<uint8_t> result(size);
    for (size_t i = 0; i < size; ++i) {
        result[i] = dist(gen);
    }
    return result;
}

std::vector<uint8_t> calculate_hash(HashAlgorithm algo, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash;
    
    switch(algo) {
        case HashAlgorithm::MD5:
            hash.resize(MD5_DIGEST_LENGTH);
            MD5(data.data(), data.size(), hash.data());
            break;
        case HashAlgorithm::SHA1:
            hash.resize(SHA_DIGEST_LENGTH);
            SHA1(data.data(), data.size(), hash.data());
            break;
        default:
            throw std::invalid_argument("Unknown hash algorithm");
    }
    return hash;
}

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (uint8_t b : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

HashAlgorithm get_algorithm_by_size(size_t hash_size) {
    switch(hash_size) {
        case 32: return HashAlgorithm::MD5;     // 128 бит
        case 40: return HashAlgorithm::SHA1;    // 160 бит  
        default: throw std::invalid_argument("Unknown hash size");
    }
}

size_t get_hash_size(HashAlgorithm algo) {
    switch(algo) {
        case HashAlgorithm::MD5: return 32;
        case HashAlgorithm::SHA1: return 40;
        default: throw std::invalid_argument("Unknown algorithm");
    }
}
