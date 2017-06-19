set(EXE_NAME ${PROJECT_NAME}_cli)

file(GLOB EXE_HEADER *.h)
file(GLOB EXE_SOURCE *.c)

add_executable(${EXE_NAME} ${EXE_SOURCE} ${EXE_HEADER})
target_link_libraries (${EXE_NAME} ${PROJECT_NAME})
