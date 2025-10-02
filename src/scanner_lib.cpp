#include "scanner_lib.h"
#include "md5.h"
#include "utils.h"
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>
#include <iostream>
#include <algorithm>

namespace Scanner {

    bool HashDatabase::loadFromCSV(const std::string& csvPath) {
        std::ifstream file(csvPath);
        if (!file.is_open()) {
            std::cerr << "Failed to open CSV file: " << csvPath << std::endl;
            return false;
        }
        
        std::string line;
        int lineNum = 0;
        while (std::getline(file, line)) {
            lineNum++;
           
            line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
            
            if (line.empty()) continue;
            
            size_t pos = line.find(';');
            if (pos == std::string::npos) {
                std::cerr << "Invalid CSV format at line " << lineNum << ": " << line << std::endl;
                continue;
            }
            
            std::string hash = line.substr(0, pos);
            std::string verdict = line.substr(pos + 1);

            std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
            
            hashes[hash] = verdict;
        }
        
        file.close();
        std::cout << "Loaded " << hashes.size() << " malicious hashes from database" << std::endl;
        return true;
    }

    bool HashDatabase::isMalicious(const std::string& hash, std::string& verdict) const {
        auto it = hashes.find(hash);
        if (it != hashes.end()) {
            verdict = it->second;
            return true;
        }
        return false;
    }

    Logger::Logger(const std::string& path) : logPath(path) {
        std::ofstream file(logPath, std::ios::trunc);
        if (file.is_open()) {
            file << "=== Malware Scanner Log ===" << std::endl;
            file << "Timestamp: " << std::chrono::system_clock::now().time_since_epoch().count() << std::endl;
            file << "===========================" << std::endl << std::endl;
            file.close();
        }
    }

    bool Logger::logMaliciousFile(const std::string& filePath, const std::string& hash, const std::string& verdict) {
        std::lock_guard<std::mutex> lock(logMutex);
        
        std::ofstream file(logPath, std::ios::app);
        if (!file.is_open()) {
            return false;
        }
        
        file << "[VIRUS!!!! ALARM!!!!] " << std::endl;
        file << "  Path: " << filePath << std::endl;
        file << "  Hash: " << hash << std::endl;
        file << "  Verdict: " << verdict << std::endl;
        file << std::endl;
        
        file.close();
        return true;
    }

    bool Logger::logError(const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);
        
        std::ofstream file(logPath, std::ios::app);
        if (!file.is_open()) {
            return false;
        }
        
        file << "[ERROR!!!!] " << message << std::endl;
        file.close();
        return true;
    }

    FileScanner::FileScanner(HashDatabase* db, Logger* log) 
        : database(db), logger(log) {
    }

    void FileScanner::incrementTotalFiles() {
        std::lock_guard<std::mutex> lock(statsMutex);
        stats.totalFiles++;
    }

    void FileScanner::incrementMaliciousFiles() {
        std::lock_guard<std::mutex> lock(statsMutex);
        stats.maliciousFiles++;
    }

    void FileScanner::incrementErrors() {
        std::lock_guard<std::mutex> lock(statsMutex);
        stats.errors++;
    }

    std::string FileScanner::calculateFileHash(const std::string& filePath, bool& success) {
        success = true;
        try {
            std::string hash = MD5::hashFile(filePath);
            return hash;
        } catch (const std::exception& e) {
            success = false;
            logger->logError("Failed to hash file: " + filePath + " - " + e.what());
            return "";
        }
    }

    void FileScanner::scanFile(const std::string& filePath) {
        incrementTotalFiles();
        
        bool success;
        std::string hash = calculateFileHash(filePath, success);
        
        if (!success) {
            incrementErrors();
            return;
        }
        
        std::string verdict;
        if (database->isMalicious(hash, verdict)) {
            incrementMaliciousFiles();
            logger->logMaliciousFile(filePath, hash, verdict);
            std::cout << "[!] Malicious file detected: " << filePath << " (" << verdict << ")" << std::endl;
        }
    }

    void FileScanner::scan(const std::string& rootPath, int threadCount) {
        auto startTime = std::chrono::high_resolution_clock::now();
        
        std::vector<std::string> files;
        Utils::getFilesRecursively(rootPath, files);
        
        std::cout << "Found " << files.size() << " files to scan" << std::endl;
        
        if (threadCount <= 0) {
            threadCount = std::thread::hardware_concurrency();
            if (threadCount == 0) threadCount = 4;
        }

        std::vector<std::thread> threads;
        size_t filesPerThread = files.size() / threadCount;
        
        for (int t = 0; t < threadCount; t++) {
            size_t start = t * filesPerThread;
            size_t end = (t == threadCount - 1) ? files.size() : (t + 1) * filesPerThread;
            
            threads.emplace_back([this, &files, start, end]() {
                for (size_t i = start; i < end; i++) {
                    scanFile(files[i]);
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        auto endTime = std::chrono::high_resolution_clock::now();
        stats.executionTimeMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    }

    struct ScannerHandle {
        HashDatabase* database;
        Logger* logger;
        FileScanner* scanner;
    };


    // Ох уж эти ДЛЛки. Не проникся ими
    extern "C" {

    SCANNER_API void* CreateScanner(const char* csvPath, const char* logPath) {
        try {
            ScannerHandle* handle = new ScannerHandle();
            
            handle->database = new HashDatabase();
            if (!handle->database->loadFromCSV(csvPath)) {
                delete handle->database;
                delete handle;
                return nullptr;
            }
            
            handle->logger = new Logger(logPath);
            handle->scanner = new FileScanner(handle->database, handle->logger);
            
            return handle;
        } catch (...) {
            return nullptr;
        }
    }

    SCANNER_API void DestroyScanner(void* scanner) {
        if (scanner) {
            ScannerHandle* handle = static_cast<ScannerHandle*>(scanner);
            delete handle->scanner;
            delete handle->logger;
            delete handle->database;
            delete handle;
        }
    }

    SCANNER_API void ScanDirectory(void* scanner, const char* path, int threadCount) {
        if (scanner) {
            ScannerHandle* handle = static_cast<ScannerHandle*>(scanner);
            handle->scanner->scan(path, threadCount);
        }
    }

    SCANNER_API void GetStatistics(void* scanner, int* total, int* malicious, int* errors, double* timeMs) {
        if (scanner) {
            ScannerHandle* handle = static_cast<ScannerHandle*>(scanner);
            ScanStatistics stats = handle->scanner->getStatistics();
            if (total) *total = stats.totalFiles;
            if (malicious) *malicious = stats.maliciousFiles;
            if (errors) *errors = stats.errors;
            if (timeMs) *timeMs = stats.executionTimeMs;
        }
    }

    } 

}