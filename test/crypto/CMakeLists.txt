
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/test_bin)

SET(KECCAK_PATH  "${PROJECT_SOURCE_DIR}/core/vendor/KeccakCodePackage")
SET(CRYPTO_PATH  "${PROJECT_SOURCE_DIR}/core/crypto")
SET(ED25519_PATH "${PROJECT_SOURCE_DIR}/core/vendor/ed25519")


set(GTEST_INCLUDE_DIR ${PROJECT_BINARY_DIR}/gtest/src/googletest/googletest/include)

FILE(GLOB_RECURSE KECCAK_OBJ ${KECCAK_PATH}/bin/.build/generic64/libkeccak.a/*.o)

include_directories(
  ${CRYPTO_PATH}
  ${GTEST_INCLUDE_DIR}
  ${ED25519_PATH}/src
  ${KECCAK_PATH}/bin/generic64/libkeccak.a.headers
)

link_directories(
  ${ED25519_PATH}
  ${PROJECT_BINARY_DIR}/lib
  ${KECCAK_PATH}/bin/generic64
)


add_executable(base64-test base64-test.cpp)
target_link_libraries(base64-test base64
  ${GTEST_LIBS_DIR}/libgtest.a ${GTEST_LIBS_DIR}/libgtest_main.a pthread)
add_test(
  NAME base64-test
  COMMAND $<TARGET_FILE:base64-test>
)


add_executable(signature-test signature-test.cpp)
target_link_libraries(signature-test signature
  base64
  ${GTEST_LIBS_DIR}/libgtest.a ${GTEST_LIBS_DIR}/libgtest_main.a pthread)
add_test(
  NAME signature-test
  COMMAND $<TARGET_FILE:signature-test>
)


add_executable(hash-test 
  ${KECCAK_PATH}
  hash-test.cpp
  ${KECCAK_PATH})
target_link_libraries(hash-test
  keccak
  hash
  ${GTEST_LIBS_DIR}/libgtest.a ${GTEST_LIBS_DIR}/libgtest_main.a pthread)
add_test(
  NAME hash-test
  COMMAND $<TARGET_FILE:hash-test>
)


