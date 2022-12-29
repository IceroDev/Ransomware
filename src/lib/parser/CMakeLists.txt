cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${CMAKE_PROJECT_NAME})

set(CMAKE_C_STANDARD ${CMAKE_C_STANDARD})

add_library(parser argument.c argument.h argument_parser.c argument_parser.h argument_parser_error.c argument_parser_error.h ../rsa/rsa.c ../rsa/rsa.h)