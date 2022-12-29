cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${CMAKE_PROJECT_NAME})

set(CMAKE_C_STANDARD ${CMAKE_C_STANDARD})

find_package(OpenSSL REQUIRED)

add_library(rsa rsa.c rsa.h)

target_link_libraries(rsa OpenSSL::SSL)