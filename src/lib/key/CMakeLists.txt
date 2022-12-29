cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${CMAKE_PROJECT_NAME})

set(CMAKE_C_STANDARD ${CMAKE_C_STANDARD})

find_package(OpenSSL REQUIRED)

add_library(key key_set.c key_set.h)
target_link_libraries(key rsa OpenSSL::SSL)