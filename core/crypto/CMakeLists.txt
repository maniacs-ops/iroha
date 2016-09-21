
SET(KECCAK_PATH  "${PROJECT_SOURCE_DIR}/core/vendor/KeccakCodePackage")
SET(ED25519_PATH "${PROJECT_SOURCE_DIR}/core/vendor/ed25519")

#SET(CMAKE_SHARED_LINKER_FLAGS "-L${KECCAK_PATH}/bin/generic64/ -lkeccak  -Wl,-ukeccak")

FILE(GLOB_RECURSE KECCAK_OBJ ${KECCAK_PATH}/bin/.build/generic64/libkeccak.a/*.o)

include_directories(${ED25519_PATH}/src)
include_directories(${KECCAK_PATH}/bin/generic64/libkeccak.a.headers)

link_directories(${ED25519_PATH})
link_directories(${KECCAK_PATH}/bin/generic64)

# Hash
ADD_LIBRARY(hash STATIC
  ${KECCAK_OBJ}
  hash.cpp
)
target_link_libraries(hash
  keccak
)

# Signature
ADD_LIBRARY(signature STATIC
  signature.cpp
)
target_link_libraries(signature
  ed25519
)

# Base64
ADD_LIBRARY(base64 STATIC base64.cpp)
