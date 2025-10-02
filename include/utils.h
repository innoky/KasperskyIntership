#include <string>
#include <windows.h>
#include <map>
#include <vector>
#include <iostream>

namespace Utils
{
    bool isValidPath(const std::string& path);

    bool isValidArgs(int argc, char* argv[]);
    
    std::map<std::string, std::string> extractArgs(int argc, char* argv[]);

    void getFilesRecursively(const std::string& path, std::vector<std::string>& files_path);
}