
#include "../../core/crypto/signature.hpp"
#include "../../core/crypto/hash.hpp"

#include <tuple>
#include <iostream>
#include <gtest/gtest.h>

#include <cstring>

TEST(Hash, sha3_256_empty){
  std::string origin = "";
  std::string result = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
  ASSERT_STREQ(hash::sha3_256_hex(origin).c_str(), result.c_str());
}

TEST(Hash, sha3_256_JP){
  std::string origin = "水樹素子";
  std::string result = "586b13bd8aa1c836ac0806012900186f23b4ccec619b85d8611515639ceab697";
  ASSERT_STREQ(hash::sha3_256_hex(origin).c_str(), result.c_str());
}

TEST(Hash, sha3_256_UnsingedChar){
  // cited by https://github.com/gvanas/KeccakCodePackage/blob/901cc1f411e1bcd7bbe40718c747922947dbea28/Tests/main.c#L431
  const unsigned char *input = (const unsigned char *)"\x21\xF1\x34\xAC\x57";
  const unsigned char *outputSHA3_256 = (const unsigned char *)
    "\x55\xBD\x92\x24\xAF\x4E\xED\x0D\x12\x11\x49\xE3\x7F\xF4\xD7\xDD"
    "\x5B\xE2\x4B\xD9\xFB\xE5\x6E\x01\x71\xE8\x7D\xB7\xA6\xF4\xE0\x6D";
  ASSERT_STREQ(
    hash::sha3_256_hex(
      std::string(reinterpret_cast<const char*>(input))
    ).c_str(), 
    reinterpret_cast<const char*>(outputSHA3_256)
  );
}

TEST(Hash, sha3_512_empty){
  std::string origin = "";
  std::string result = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
  ASSERT_STREQ(
    hash::sha3_256_hex(
      origin
    ).c_str(),
    result.c_str()
  );
}

TEST(Hash, sha3_512_JP){
  std::string origin = "水樹素子";
  std::string result = "bd56fbc1c356368b0d9e9311c5b787e1db0cabd697dad274dcc1b0da94ccb96c04a73ef13be6e7606e48d43d518ad302bf8509818d907c6cbf00b61b984e36b9";
  ASSERT_STREQ(
    hash::sha3_256_hex(origin).c_str(),
    result.c_str()
  );
}

TEST(Hash, sha3_512_UnsingedChar){
  // cited by https://github.com/gvanas/KeccakCodePackage/blob/901cc1f411e1bcd7bbe40718c747922947dbea28/Tests/main.c#L431
  const unsigned char *input = (const unsigned char *)"\x21\xF1\x34\xAC\x57";
  const unsigned char *outputSHA3_512 = (const unsigned char *)
        "\x58\x42\x19\xA8\x4E\x87\x96\x07\x6B\xF1\x17\x8B\x14\xB9\xD1\xE2"
        "\xF9\x6A\x4B\x4E\xF1\x1F\x10\xCC\x51\x6F\xBE\x1A\x29\x63\x9D\x6B"
        "\xA7\x4F\xB9\x28\x15\xF9\xE3\xC5\x19\x2E\xD4\xDC\xA2\x0A\xEA\x5B"
        "\x10\x9D\x52\x23\x7C\x99\x56\x40\x1F\xD4\x4B\x22\x1F\x82\xAB\x37";
  ASSERT_STREQ(
    hash::sha3_256_hex(
      std::string(reinterpret_cast<const char*>(input))
    ).c_str(), 
    reinterpret_cast<const char*>(outputSHA3_512)
  );
}


