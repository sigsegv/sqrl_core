# Tarsnap scrypt encryption utility.
# http://www.tarsnap.com/scrypt.html

file(GLOB_RECURSE SRC *.c)
file(GLOB_RECURSE HDR *.h)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/lib/crypto
	${CMAKE_CURRENT_SOURCE_DIR}/lib/util
	${CMAKE_CURRENT_SOURCE_DIR}/lib/scryptenc
)
add_library(scrypt ${SRC} ${HDR})
