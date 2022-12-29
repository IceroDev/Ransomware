cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(victim C)

set(CMAKE_C_STANDARD ${CMAKE_C_STANDARD})

find_package(OpenSSL REQUIRED)

add_executable(victim main.c option/option.c option/option.h evp/evp.c evp/evp.h)
target_link_libraries(victim OpenSSL::SSL)