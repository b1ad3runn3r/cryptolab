cmake_minimum_required(VERSION 3.20)
project("LAB1" CXX)

set(CMAKE_CXX_STANDARD 20)
# set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_library(ike_commons STATIC src/ike_common.h src/ike_common.cpp)

add_executable(generator src/gen.cpp)
target_link_libraries(generator ike_commons OpenSSL::Crypto)

add_executable(crack src/crack.cpp)
target_link_libraries(crack ike_commons OpenSSL::Crypto)
