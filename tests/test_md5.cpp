#include <gtest/gtest.h>
#include "md5.h"
#include <fstream>

class MD5Test : public ::testing::Test {
protected:
    void SetUp() override {
        std::ofstream file("test_file.txt");
        file << "Hello, World!";
        file.close();
    }
    
    void TearDown() override {
     
        std::remove("test_file.txt");
    }
};

TEST_F(MD5Test, BasicStringHash) {
    std::string input = "test";
    std::string expected = "098f6bcd4621d373cade4e832627b4f6";
    EXPECT_EQ(MD5::hash(input), expected);
}

TEST_F(MD5Test, EmptyString) {
    std::string input = "";
    std::string expected = "d41d8cd98f00b204e9800998ecf8427e";
    EXPECT_EQ(MD5::hash(input), expected);
}

TEST_F(MD5Test, LongString) {
    std::string input = "The quick brown fox jumps over the lazy dog";
    std::string expected = "9e107d9d372bb6826bd81d3542a419d6";
    EXPECT_EQ(MD5::hash(input), expected);
}

TEST_F(MD5Test, FileHashing) {
    std::string hash = MD5::hashFile("test_file.txt");
    EXPECT_EQ(hash.length(), 32); 
    
    std::string expected = "65a8e27d8879283831b664bd8b7f0ad4";
    EXPECT_EQ(hash, expected);
}

TEST_F(MD5Test, NonExistentFile) {
    EXPECT_THROW(MD5::hashFile("nonexistent_file.txt"), std::runtime_error);
}

TEST_F(MD5Test, HashConsistency) {
    std::string input = "consistency test";
    std::string hash1 = MD5::hash(input);
    std::string hash2 = MD5::hash(input);
    EXPECT_EQ(hash1, hash2);
}