#pragma once 
#include <string>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <cstdint>
#include <vector>

class MD5 {
public:
    static std::string hash(const std::string& data);
    static std::string hashFile(const std::string& path);

private:
    static uint32_t rotateLeft(uint32_t value, int count) {
        return (value << count) | (value >> (32 - count));
    }

    static void processBlock(const uint8_t* block, uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D);
};