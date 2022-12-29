cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(lib)

set(CMAKE_C_STANDARD ${CMAKE_C_STANDARD})

add_subdirectory(key)
add_subdirectory(parser)
add_subdirectory(rsa)
add_subdirectory(tcp)
add_subdirectory(util)

target_link_libraries(attacker key rsa tcp util)
target_link_libraries(victim key parser rsa tcp util)