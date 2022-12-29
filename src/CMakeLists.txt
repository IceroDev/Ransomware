cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${CMAKE_PROJECT_NAME})

set(CMAKE_C_STANDARD ${CMAKE_C_STANDARD})

add_subdirectory(attacker)
add_subdirectory(victim)

add_subdirectory(lib)