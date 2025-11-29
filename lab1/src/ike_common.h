#ifndef IKE_COMMON_H
#define IKE_COMMON_H

#include <vector>
#include <string>
#include <cstdint>

enum class HashAlgorithm { 
    MD5, SHA1, SHA256, SHA384, SHA512 
};

std::vector<uint8_t> generate_random_data(size_t size, uint32_t seed);
std::vector<uint8_t> calculate_hash(HashAlgorithm algo, const std::vector<uint8_t>& data);
std::string bytes_to_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hex_to_bytes(const std::string& hex);
HashAlgorithm get_algorithm_by_size(size_t hash_size);
size_t get_hash_size(HashAlgorithm algo);

#endif
