#include "ike_common.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <random>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <span>
#include <cstring>

std::vector<uint8_t> generate_random_data(size_t size, uint32_t seed) {
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    std::vector<uint8_t> result(size);
    for (size_t i = 0; i < size; ++i) {
        result[i] = dist(gen);
    }
    return result;
}

void __calculate_hash(
    HashAlgorithm algo,
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t *dst_len
) {
    switch(algo) {
        case HashAlgorithm::MD5:
            *dst_len = MD5_DIGEST_LENGTH;
            MD5(src, src_len, dst);
            break;
        case HashAlgorithm::SHA1:
            *dst_len = SHA_DIGEST_LENGTH;
            SHA1(src, src_len, dst);
            break;
        default:
            throw std::invalid_argument("Unknown hash algorithm");
    }
}

void new_calculate_hmac(
    HashAlgorithm algo,
    const uint8_t *key,
    size_t key_size,
    const uint8_t *data,
    size_t data_size,
    uint8_t *out,
    size_t *out_size
)
{
    constexpr size_t block_size = 64;
    uint8_t prepared_key[block_size] = {0};
    size_t prepared_key_size = 0;

    if (key_size > block_size) {
        __calculate_hash(algo, key, key_size, prepared_key, &prepared_key_size);
    }
    else {
        std::memcpy(prepared_key, key, key_size);
    }

    uint8_t ipad[block_size];
    std::memset(ipad, 0x36, block_size);

    uint8_t opad[block_size];
    std::memset(opad, 0x5c, block_size);

    auto *inner_key = new uint8_t[block_size + data_size];
    if (inner_key == nullptr) {
        throw std::runtime_error("Alloc error");
    }

    for (size_t i = 0; i < block_size; ++i) {
        inner_key[i] = prepared_key[i] ^ ipad[i];
    }

    std::memcpy(inner_key + block_size, data, data_size);

    uint8_t inner_hash[block_size] = {0};
    size_t inner_hash_size = 0;

    __calculate_hash(algo, inner_key, block_size + data_size, inner_hash, &inner_hash_size);

    auto *outer_key = new uint8_t[block_size + inner_hash_size];
    if (outer_key == nullptr) {
        throw std::runtime_error("Alloc error");
    }

    for (size_t i = 0; i < block_size; ++i) {
        outer_key[i] = prepared_key[i] ^ opad[i];
    }

    std::memcpy(outer_key + block_size, inner_hash, inner_hash_size);
    __calculate_hash(algo, outer_key, block_size + inner_hash_size, out, out_size);

    delete[] inner_key;
    delete[] outer_key;
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
        case 32: return HashAlgorithm::MD5;
        case 40: return HashAlgorithm::SHA1;
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
