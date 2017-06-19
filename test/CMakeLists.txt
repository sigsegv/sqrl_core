set(TEST_NAME ${PROJECT_NAME}_test)

file(GLOB HDR *.h)
file(GLOB SRC *.c)

include_directories(
    ../lib
    ../lib/thirdparty/aes-gcm
    ${LIBSODIUM_INCLUDE}
)
add_executable(${TEST_NAME} ${SRC} ${HDR})
target_link_libraries (${TEST_NAME} ${PROJECT_NAME})