find_file(LIBSODIUM_LIB libSodium DOC “Path to lib sodium static library” NO_DEFAULT_PATH)
find_path(LIBSODIUM_INCLUDE libSodiumInc DOC “Path to lib sodium include directory” NO_DEFAULT_PATH)

add_subdirectory(thirdparty)
add_subdirectory(net)

set(CONFIG_HDR config.h)
set(CRYPTO_DEP_HDR crypto_dep.h)

file(GLOB LIB_HEADER *.h)
file(GLOB LIB_SOURCE *.c)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBSODIUM_INCLUDE}
    thirdparty
)

set(STATIC_LIBS ${LIBSODIUM_LIB} aesgcm)

include(net/apple/CMakeLists.txt)

add_library(${PROJECT_NAME} STATIC ${LIB_HEADER} ${LIB_SOURCE} )
target_link_libraries(${PROJECT_NAME} ${STATIC_LIBS})
