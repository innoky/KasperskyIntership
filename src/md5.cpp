#include "md5.h"
#include <fstream>
#include <stdexcept>

void MD5::processBlock(const uint8_t* block, uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D) {

    /*
    Это вообще песня... Как я понял можно было юзать хеширование
    из библиотеки типа опенссл и не париться над реализацией хеширование,
    но я видимо не понял ТЗшку)) Часов 6-8 потратил, чтобы разобраться
    с хешированием, ибо впервые в жизни пишу МД5. Вышло как-то так.
    Смотрел разные реализации из интернета и советовался с ГПТшкой, но
    принцип работы понимаю. Конечно, почему беруться именно такие регистры
    и другие детали не расскажу, но сам принцип понимаю. 
    
    */
    static uint32_t T[64];
    static bool initialized = false;
    
    if (!initialized) {
        for (int i = 0; i < 64; ++i)
            T[i] = (uint32_t)(std::floor(std::pow(2, 32) * std::abs(std::sin(i + 1))));
        initialized = true;
    }
    
    static const uint32_t s[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };
    
    uint32_t M[16];
    for (int i = 0; i < 16; ++i) {
        M[i] = (uint32_t)block[i*4] |
            ((uint32_t)block[i*4 + 1] << 8) |
            ((uint32_t)block[i*4 + 2] << 16) |
            ((uint32_t)block[i*4 + 3] << 24);
    }
    
    uint32_t AA = A, BB = B, CC = C, DD = D;
    
    for (int i = 0; i < 64; ++i) {
        uint32_t F, k;
        if (i < 16) { 
            F = (B & C) | (~B & D); 
            k = i; 
        }
        else if (i < 32) { 
            F = (B & D) | (C & ~D); 
            k = (5*i + 1) % 16; 
        }
        else if (i < 48) { 
            F = B ^ C ^ D; 
            k = (3*i + 5) % 16; 
        }
        else { 
            F = C ^ (B | ~D); 
            k = (7*i) % 16; 
        }
        
        uint32_t temp = D;
        D = C;
        C = B;
        B = B + rotateLeft(A + F + M[k] + T[i], s[i]);
        A = temp;
    }
    
    A += AA;
    B += BB;
    C += CC;
    D += DD;
}

std::string MD5::hash(const std::string& input) {
    uint32_t A = 0x67452301;
    uint32_t B = 0xefcdab89;
    uint32_t C = 0x98badcfe;
    uint32_t D = 0x10325476;
    
    std::vector<uint8_t> data(input.begin(), input.end());
    uint64_t bit_len = data.size() * 8;
    
    data.push_back(0x80);
    while ((data.size() * 8) % 512 != 448) 
        data.push_back(0x00);
    
    for (int i = 0; i < 8; ++i)
        data.push_back(static_cast<uint8_t>((bit_len >> (8*i)) & 0xFF));
    
    for (size_t offset = 0; offset < data.size(); offset += 64) {
        processBlock(&data[offset], A, B, C, D);
    }
    
    std::ostringstream result;
    for (uint32_t x : {A, B, C, D}) {
        for (int i = 0; i < 4; ++i)
            result << std::hex << std::setw(2) << std::setfill('0') 
                << ((x >> (8*i)) & 0xFF);
    }
    
    return result.str();
}

std::string MD5::hashFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    
    uint32_t A = 0x67452301;
    uint32_t B = 0xefcdab89;
    uint32_t C = 0x98badcfe;
    uint32_t D = 0x10325476;
    
    const size_t BUFFER_SIZE = 1024 * 1024;
    std::vector<uint8_t> buffer;
    uint64_t totalBytes = 0;
    
    char chunk[BUFFER_SIZE];
    while (file.read(chunk, BUFFER_SIZE) || file.gcount() > 0) {
        size_t bytesRead = file.gcount();
        buffer.insert(buffer.end(), chunk, chunk + bytesRead);
        totalBytes += bytesRead;
        
        while (buffer.size() >= 64) {
            processBlock(buffer.data(), A, B, C, D);
            buffer.erase(buffer.begin(), buffer.begin() + 64);
        }
    }
    
    file.close();
    
    uint64_t bit_len = totalBytes * 8;
    buffer.push_back(0x80);
    
    while ((buffer.size() * 8) % 512 != 448) 
        buffer.push_back(0x00);
    
    for (int i = 0; i < 8; ++i)
        buffer.push_back(static_cast<uint8_t>((bit_len >> (8*i)) & 0xFF));
    
    for (size_t offset = 0; offset < buffer.size(); offset += 64) {
        processBlock(&buffer[offset], A, B, C, D);
    }
    
    std::ostringstream result;
    for (uint32_t x : {A, B, C, D}) {
        for (int i = 0; i < 4; ++i)
            result << std::hex << std::setw(2) << std::setfill('0') 
                << ((x >> (8*i)) & 0xFF);
    }
    
    return result.str();
}