#include <gtest/gtest.h>
#include "scanner_lib.h"
#include "md5.h"
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

class ScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
     
        std::ofstream csv("test_base.csv");
        csv << "098f6bcd4621d373cade4e832627b4f6;TestVirus\n";
        csv << "5d41402abc4b2a76b9719d911017c592;TestTrojan\n";
        csv.close();
        
      
        fs::create_directory("test_scan_dir");
        std::ofstream("test_scan_dir/malicious.txt") << "test";  
        std::ofstream("test_scan_dir/clean.txt") << "clean file content";
    }
    
    void TearDown() override {
        std::remove("test_base.csv");
        std::remove("test_log.txt");
        fs::remove_all("test_scan_dir");
    }
};

TEST_F(ScannerTest, LoadHashDatabase) {
    Scanner::HashDatabase db;
    EXPECT_TRUE(db.loadFromCSV("test_base.csv"));
    EXPECT_EQ(db.size(), 2);
}

TEST_F(ScannerTest, DetectMaliciousHash) {
    Scanner::HashDatabase db;
    db.loadFromCSV("test_base.csv");
    
    std::string verdict;
    EXPECT_TRUE(db.isMalicious("098f6bcd4621d373cade4e832627b4f6", verdict));
    EXPECT_EQ(verdict, "TestVirus");
}

TEST_F(ScannerTest, DetectCleanHash) {
    Scanner::HashDatabase db;
    db.loadFromCSV("test_base.csv");
    
    std::string verdict;
    EXPECT_FALSE(db.isMalicious("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", verdict));
}

TEST_F(ScannerTest, LoggerCreation) {
    Scanner::Logger logger("test_log.txt");
    EXPECT_TRUE(fs::exists("test_log.txt"));
}

TEST_F(ScannerTest, LogMaliciousFile) {
    Scanner::Logger logger("test_log.txt");
    EXPECT_TRUE(logger.logMaliciousFile("C:\\test.exe", "abc123", "Trojan"));
    
    
    std::ifstream log("test_log.txt");
    std::string content((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
    EXPECT_GT(content.length(), 0);
}

TEST_F(ScannerTest, FullScanTest) {
    Scanner::HashDatabase db;
    db.loadFromCSV("test_base.csv");
    
    Scanner::Logger logger("test_log.txt");
    Scanner::FileScanner scanner(&db, &logger);
    
    scanner.scan("test_scan_dir", 2);
    
    Scanner::ScanStatistics stats = scanner.getStatistics();
    EXPECT_EQ(stats.totalFiles, 2);
    EXPECT_EQ(stats.maliciousFiles, 1); 
    EXPECT_GE(stats.executionTimeMs, 0);
}

TEST_F(ScannerTest, CAPITest) {
    void* scanner = Scanner::CreateScanner("test_base.csv", "test_log.txt");
    EXPECT_NE(scanner, nullptr);
    
    Scanner::ScanDirectory(scanner, "test_scan_dir", 2);
    
    int total = 0, malicious = 0, errors = 0;
    double timeMs = 0.0;
    Scanner::GetStatistics(scanner, &total, &malicious, &errors, &timeMs);
    
    EXPECT_EQ(total, 2);
    EXPECT_EQ(malicious, 1);
    
    Scanner::DestroyScanner(scanner);
}