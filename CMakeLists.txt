cmake_minimum_required(VERSION 3.0)
set(PROJECT_NAME pemberton)

project(${PROJECT_NAME})

set(OUTPUT_DIR ${CMAKE_BINARY_DIR}/output)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIR})

include (${CMAKE_SOURCE_DIR}/local_settings.cmake OPTIONAL)

add_subdirectory(lib)
add_subdirectory(cli)
add_subdirectory(test)
