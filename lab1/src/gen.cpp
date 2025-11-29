#include "ike_common.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <map>

int main(int argc, char* argv[]) {
    if (argc != 5 || std::strcmp(argv[1], "-m") != 0 || std::strcmp(argv[3], "-p") != 0) {
        std::cerr << "Usage: " << argv[0] << " -m md5|sha1 -p <password>" << std::endl;
        return 1;
    }

    std::map<std::string, HashAlgorithm> algo_map = {
        {"md5", HashAlgorithm::MD5},
        {"sha1", HashAlgorithm::SHA1},
    };

    std::string algo_str = argv[2];
    if (algo_map.find(algo_str) == algo_map.end()) {
        std::cerr << "Unknown algorithm: " << algo_str << std::endl;
        return 1;
    }

    HashAlgorithm algo = algo_map[algo_str];
    const std::string password = argv[4];
    uint32_t seed = std::hash<std::string>{}(password);

    auto Ni = generate_random_data(16, seed + 1);   // Nonce initiator
    auto Nr = generate_random_data(16, seed + 2);   // Nonce responder
    auto g_x = generate_random_data(96, seed + 3);  // DH public value initiator
    auto g_y = generate_random_data(96, seed + 4);  // DH public value responder
    auto Ci = generate_random_data(4, seed + 5);    // Cookie initiator
    auto Cr = generate_random_data(4, seed + 6);    // Cookie responder
    auto SAi = generate_random_data(16, seed + 7);  // SA initiator
    auto IDi = generate_random_data(16, seed + 8);  // ID initiator

    std::vector<uint8_t> hash_data;
    hash_data.insert(hash_data.end(), password.begin(), password.end());
    hash_data.insert(hash_data.end(), Ni.begin(), Ni.end());
    hash_data.insert(hash_data.end(), Nr.begin(), Nr.end());
    hash_data.insert(hash_data.end(), g_x.begin(), g_x.end());
    hash_data.insert(hash_data.end(), g_y.begin(), g_y.end());
    hash_data.insert(hash_data.end(), Ci.begin(), Ci.end());
    hash_data.insert(hash_data.end(), Cr.begin(), Cr.end());
    hash_data.insert(hash_data.end(), SAi.begin(), SAi.end());
    hash_data.insert(hash_data.end(), IDi.begin(), IDi.end());

    auto HASH = calculate_hash(algo, hash_data);

    std::cout << bytes_to_hex(Ni) << "*"
              << bytes_to_hex(Nr) << "*"
              << bytes_to_hex(g_x) << "*"
              << bytes_to_hex(g_y) << "*"
              << bytes_to_hex(Ci) << "*"
              << bytes_to_hex(Cr) << "*"
              << bytes_to_hex(SAi) << "*"
              << bytes_to_hex(IDi) << "*"
              << bytes_to_hex(HASH) << std::endl;

    return 0;
}
