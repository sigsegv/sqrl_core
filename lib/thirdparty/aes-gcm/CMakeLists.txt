# AES-GCM public domain implementations by Steve Gibson
# https://www.grc.com/sqrl/files/AES-GCM.zip

file(GLOB_RECURSE SRC *.c)
file(GLOB_RECURSE HDR *.h)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
)
add_library(aesgcm ${SRC} ${HDR})
