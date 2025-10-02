cmake_minimum_required(VERSION 3.14)

project(scanner)
set(CMAKE_TLS_VERIFY 0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    if(MINGW)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    endif()
endif()

add_library(CommonLib STATIC
    "src/md5.cpp"
    "include/md5.h"
    "src/utils.cpp"
    "include/utils.h"
)

target_include_directories(CommonLib PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_library(ScannerLib SHARED
    src/scanner_lib.cpp
    include/scanner_lib.h
)

target_include_directories(ScannerLib PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ScannerLib PRIVATE CommonLib)

target_compile_definitions(ScannerLib PRIVATE SCANNER_DLL_EXPORT)

add_executable(scanner
    src/main.cpp
)

target_include_directories(scanner PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(scanner PRIVATE ScannerLib CommonLib)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/release-1.12.1.zip
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(scanner_tests
    tests/test_md5.cpp
    tests/test_scanner.cpp
)

target_include_directories(scanner_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(scanner_tests PRIVATE 
    ScannerLib
    CommonLib
    gtest_main
)

include(GoogleTest)
gtest_discover_tests(scanner_tests)