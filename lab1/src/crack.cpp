#include "ike_common.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>

std::vector<std::string> split(const std::string& s, char delimiter);

class ThreadSafePasswordGenerator {
public:
    ThreadSafePasswordGenerator(const std::string& mask) : mask_(mask) {
        for (char c : mask) {
            alphabets_.push_back(get_alphabet(c));
            alphabet_sizes_.push_back(alphabets_.back().size());
        }

        total_combinations_ = 1;
        for (size_t size : alphabet_sizes_) {
            total_combinations_ *= size;
        }
    }

    std::string get_password(uint64_t index) {
        std::string password(mask_.size(), ' ');
        uint64_t temp = index;

        for (int i = mask_.size() - 1; i >= 0; --i) {
            uint64_t alphabet_size = alphabet_sizes_[i];
            uint64_t char_index = temp % alphabet_size;
            password[i] = alphabets_[i][char_index];
            temp /= alphabet_size;
        }

        return password;
    }

    uint64_t get_total_combinations() const {
        return total_combinations_;
    }

private:
    std::string get_alphabet(char type) {
        switch (type) {
            case 'a': return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            case 'd': return "0123456789";
            case 'l': return "abcdefghijklmnopqrstuvwxyz";
            case 'u': return "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            default: throw std::invalid_argument("Invalid mask character");
        }
    }

    std::string mask_;
    std::vector<std::string> alphabets_;
    std::vector<uint64_t> alphabet_sizes_;
    uint64_t total_combinations_;
};


std::atomic<bool> password_found(false);
std::atomic<uint64_t> attempts(0);
std::mutex cout_mutex;
std::string found_password;


void worker_thread(
    ThreadSafePasswordGenerator& generator,
    const std::vector<uint8_t>& fixed_data,
    const std::vector<uint8_t>& target_hash,
    HashAlgorithm algo,
    uint64_t start_index,
    uint64_t end_index,
    int thread_id) {

    for (uint64_t i = start_index; i < end_index && !password_found; ++i) {
        std::string password = generator.get_password(i);
        uint64_t current_attempts = ++attempts;

        if (current_attempts % 100000 == 0) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Thread " << thread_id << " - Attempt " << current_attempts
            << ": " << password << std::endl;
        }

        std::vector<uint8_t> data;
        data.insert(data.end(), password.begin(), password.end());
        data.insert(data.end(), fixed_data.begin(), fixed_data.end());

        auto test_hash = calculate_hash(algo, data);
        if (test_hash == target_hash) {
            password_found = true;
            found_password = password;

            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << " Found in thread" << thread_id
            << " ***: " << password
            << " (after " << current_attempts << " attempts)" << std::endl;
            return;
        }
    }
    }

    int main(int argc, char* argv[]) {
        if (argc != 4 || std::strcmp(argv[1], "--mask") != 0) {
            std::cerr << "Usage: " << argv[0] << " --mask <mask> <test_file>" << std::endl;
            return 1;
        }

        std::string mask = argv[2];
        std::ifstream file(argv[3]);
        if (!file.is_open()) {
            std::cerr << "Cannot open file: " << argv[3] << std::endl;
            return 1;
        }

        std::string line;
        std::getline(file, line);
        auto parts = split(line, '*');
        if (parts.size() != 9) {
            std::cerr << "Invalid file format" << std::endl;
            return 1;
        }

        HashAlgorithm algo = get_algorithm_by_size(parts[8].size());

        auto Ni = hex_to_bytes(parts[0]);
        auto Nr = hex_to_bytes(parts[1]);
        auto g_x = hex_to_bytes(parts[2]);
        auto g_y = hex_to_bytes(parts[3]);
        auto Ci = hex_to_bytes(parts[4]);
        auto Cr = hex_to_bytes(parts[5]);
        auto SAi = hex_to_bytes(parts[6]);
        auto IDi = hex_to_bytes(parts[7]);
        auto HASH = hex_to_bytes(parts[8]);

        std::vector<uint8_t> fixed_data;
        fixed_data.insert(fixed_data.end(), Ni.begin(), Ni.end());
        fixed_data.insert(fixed_data.end(), Nr.begin(), Nr.end());
        fixed_data.insert(fixed_data.end(), g_x.begin(), g_x.end());
        fixed_data.insert(fixed_data.end(), g_y.begin(), g_y.end());
        fixed_data.insert(fixed_data.end(), Ci.begin(), Ci.end());
        fixed_data.insert(fixed_data.end(), Cr.begin(), Cr.end());
        fixed_data.insert(fixed_data.end(), SAi.begin(), SAi.end());
        fixed_data.insert(fixed_data.end(), IDi.begin(), IDi.end());

        ThreadSafePasswordGenerator generator(mask);
        uint64_t total_combinations = generator.get_total_combinations();

        std::cout << "Starting multithreaded cracking with " << total_combinations
        << " possible passwords" << std::endl;

        unsigned int num_threads = std::thread::hardware_concurrency();

        std::cout << "Using " << num_threads << " threads" << std::endl;

        uint64_t combinations_per_thread = total_combinations / num_threads;
        std::vector<std::thread> threads;

        auto start_time = std::chrono::steady_clock::now();

        for (unsigned int i = 0; i < num_threads; ++i) {
            uint64_t start = i * combinations_per_thread;
            uint64_t end = (i == num_threads - 1) ? total_combinations : start + combinations_per_thread;

            threads.emplace_back(worker_thread,
                                 std::ref(generator),
                                 std::cref(fixed_data),
                                 std::cref(HASH),
                                 algo,
                                 start,
                                 end,
                                 i);
        }

        for (auto& thread : threads) {
            thread.join();
        }

        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        if (password_found) {
            std::cout << "SUCCESS: Password '" << found_password
            << "' found in " << duration.count() << " ms" << std::endl;
            return 0;
        } else {
            std::cout << "FAILURE: Password not found after " << attempts
            << " attempts in " << duration.count() << " ms" << std::endl;
            return 1;
        }
    }

    std::vector<std::string> split(const std::string& s, char delimiter) {
        std::vector<std::string> tokens;
        size_t start = 0, end = 0;
        while ((end = s.find(delimiter, start)) != std::string::npos) {
            tokens.push_back(s.substr(start, end - start));
            start = end + 1;
        }
        tokens.push_back(s.substr(start));
        return tokens;
    }
