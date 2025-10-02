#include "utils.h"


bool Utils::isValidPath(const std::string& path) {
    if (GetFileAttributes(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    return true;
}

bool Utils::isValidArgs(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    for (int i = 1; i < argc; i++) {
        std::string key(argv[i]);

        if (key.rfind("--", 0) == 0) {
            if (i + 1 < argc)
                args[key.substr(2)] = argv[i + 1];
            else
                throw std::runtime_error("Invalid arguments. Usage: scanner --path <path> --base <base> --log <log>");
            i++;
        } else {
            throw std::runtime_error("Invalid arguments. Usage: scanner --path <path> --base <base> --log <log>");
        }
    }
    return args.count("path") && args.count("base") && args.count("log");
}

std::map<std::string, std::string> Utils::extractArgs(int argc, char* argv[]) {
    std::map<std::string, std::string> args;

    for (int i = 1; i < argc; i++) {
        std::string key(argv[i]);

        if (key.rfind("--", 0) == 0) {
            if (i + 1 < argc) {
                args[key.substr(2)] = argv[i + 1];
                i++;
            } else {
                throw std::runtime_error("Missing value for argument: " + key);
            }
        } else {
            throw std::runtime_error("Unexpected argument: " + key);
        }
    }
    return args;
}

void Utils::getFilesRecursively(const std::string& path, std::vector<std::string>& files_path) {
    WIN32_FIND_DATAA find_data;
    HANDLE hFind;

    std::string search_path = path + "\\*";
    hFind = FindFirstFileA(search_path.c_str(), &find_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Error finding files in path: " << path << std::endl;
        return;
    }

    do {
        std::string name = find_data.cFileName;

        if (name != "." && name != "..") {
            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                getFilesRecursively(path + "\\" + name, files_path);
            } else {
                files_path.push_back(path + "\\" + name);
            }
        }
    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);
}

