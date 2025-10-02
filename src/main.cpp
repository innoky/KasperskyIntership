#include <iostream>
#include <string>
#include <iomanip>

#include "utils.h"
#include "scanner_lib.h"

namespace Printer{
    void printUsage() {
        printf("Usage: scanner.exe --base <csv_file> --log <log_file> --path <directory>\n");
        printf("  --base  CSV file with hash values of malicious files\n");
        printf("  --log   Log file\n");
        printf("  --path  Root directory for scanning\n");
    }
    
    void printReport(int total, int malicious, int errors, double timeMs) {
        printf("\n============== Report =================\n");
        printf("Total files processed:    %d\n", total);
        printf("Malicious files detected: %d\n", malicious);
        printf("Errors encountered:       %d\n", errors);
        printf("Execution time:           %.2f ms (%.2f seconds)\n", timeMs, timeMs / 1000.0);
        printf("================== End =================\n");
    }
}

int main(int argc, char* argv[]) {
    /*
        PowerShell неприятная штука, которая использует непонятно какую кодировку,
        поэтому я не стал париться с выводом русского текста.
        Выводы программы пишем на англиском языке.
    */
    SetConsoleOutputCP(CP_UTF8);
    setlocale(LC_ALL, "");
    printf("=== Megascanner on internship started ===\n");
    
    if (!Utils::isValidArgs(argc, argv)) {
        std::cerr << "Error: Invalid arguments" << std::endl;
        Printer::printUsage();
        return 1;
    }
    
    auto args = Utils::extractArgs(argc, argv);
    
    std::string basePath = args["base"];
    std::string logPath = args["log"];
    std::string scanPath = args["path"];
    
    printf("Arguments:\n");
    printf("Hash database: %s\n", basePath.c_str());
    printf("Log file: %s\n", logPath.c_str());
    printf("Scan path: %s\n", scanPath.c_str());
    printf("\n");
    
    if (!Utils::isValidPath(scanPath)) {
        std::cerr << "Error: Path does not exist or is not accessible: " << scanPath << std::endl;
        return 1;
    }
    
    void* scanner = Scanner::CreateScanner(basePath.c_str(), logPath.c_str());
    if (!scanner) {
        std::cerr << "Error: Failed to initialize scanner. Check if hash database exists." << std::endl;
        return 1;
    }
    
    printf("Scanner successfully started\n");
    printf("Virus search started, be scared!\n\n");
    
    Scanner::ScanDirectory(scanner, scanPath.c_str(), 0);
    
    int total = 0, malicious = 0, errors = 0;
    double timeMs = 0.0;
    Scanner::GetStatistics(scanner, &total, &malicious, &errors, &timeMs);
    
    Printer::printReport(total, malicious, errors, timeMs);
    
    Scanner::DestroyScanner(scanner);
    
    printf("\nScanner finished. Check %s for logs.\n", logPath.c_str());
    
    return 0;
}