#pragma once
#include <string>
#include <map>
#include <vector>
#include <mutex>

#ifdef _WIN32
    #ifdef SCANNER_DLL_EXPORT
        #define SCANNER_API __declspec(dllexport)
    #else
        #define SCANNER_API __declspec(dllimport)
    #endif
#else
    #define SCANNER_API
#endif

namespace Scanner {

struct ScanStatistics {
    int totalFiles = 0;
    int maliciousFiles = 0;
    int errors = 0;
    double executionTimeMs = 0.0;
};

class SCANNER_API HashDatabase {
private:
    std::map<std::string, std::string> hashes; 
    
public:
    bool loadFromCSV(const std::string& csvPath);
    bool isMalicious(const std::string& hash, std::string& verdict) const;
    size_t size() const { return hashes.size(); }
};


class SCANNER_API Logger {
    private:
        std::string logPath;
        std::mutex logMutex;
        
    public:
        Logger(const std::string& path);
        bool logMaliciousFile(const std::string& filePath, const std::string& hash, const std::string& verdict);
        bool logError(const std::string& message);
};


class SCANNER_API FileScanner {
private:
    HashDatabase* database;
    Logger* logger;
    ScanStatistics stats;
    std::mutex statsMutex;
    
    void scanFile(const std::string& filePath);
    std::string calculateFileHash(const std::string& filePath, bool& success);
    
public:
    FileScanner(HashDatabase* db, Logger* log);
    
    void scan(const std::string& rootPath, int threadCount = 0);
    ScanStatistics getStatistics() const { return stats; }
    
    void incrementTotalFiles();
    void incrementMaliciousFiles();
    void incrementErrors();
};


extern "C" {
    SCANNER_API void* CreateScanner(const char* csvPath, const char* logPath);
    SCANNER_API void DestroyScanner(void* scanner);
    SCANNER_API void ScanDirectory(void* scanner, const char* path, int threadCount);
    SCANNER_API void GetStatistics(void* scanner, int* total, int* malicious, int* errors, double* timeMs);
}

} 