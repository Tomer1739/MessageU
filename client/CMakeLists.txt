cmake_minimum_required(VERSION 3.15)

project(MessageUClient CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# crypto++ is built with the static runtime (/MT) by default on Visual Studio, so use the same
option(MSVC_STATIC_RUNTIME "Link with the static MSVC runtime (/MT), like the default crypto++ build" ON)
if(MSVC_STATIC_RUNTIME)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# the code includes <cryptopp880/...>, so we find the crypto++ headers
# and copy them into build/include/cryptopp880
find_path(CRYPTOPP_HEADERS aes.h
    PATH_SUFFIXES cryptopp880 cryptopp crypto++
    DOC "Folder that holds the crypto++ headers (aes.h, rsa.h, ...)")
find_library(CRYPTOPP_LIBRARY
    NAMES cryptlib cryptopp crypto++
    HINTS ${CRYPTOPP_HEADERS}
    PATH_SUFFIXES x64/Output/Release Win32/Output/Release lib
    DOC "crypto++ library file (cryptlib.lib on Windows, libcryptopp on Linux)")

if(NOT CRYPTOPP_HEADERS OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "crypto++ not found. Set CRYPTOPP_HEADERS and CRYPTOPP_LIBRARY, for example:\n"
        "  -DCRYPTOPP_HEADERS=C:/cryptopp880 -DCRYPTOPP_LIBRARY=C:/cryptopp880/x64/Output/Release/cryptlib.lib")
endif()

file(GLOB CRYPTOPP_HEADER_FILES "${CRYPTOPP_HEADERS}/*.h")
file(COPY ${CRYPTOPP_HEADER_FILES} DESTINATION "${CMAKE_BINARY_DIR}/include/cryptopp880")

# boost asio is header only
find_package(Boost REQUIRED)
find_package(Threads REQUIRED)

add_executable(MessageUClient
    main.cpp
    messageuclient.cpp
    networkmanager.cpp
    protocol.cpp
    models.cpp
    AESWrapper.cpp
    RSAWrapper.cpp
    Base64Wrapper.cpp
)

target_include_directories(MessageUClient PRIVATE "${CMAKE_BINARY_DIR}/include")
target_link_libraries(MessageUClient PRIVATE ${CRYPTOPP_LIBRARY} Boost::boost Threads::Threads)

if(WIN32)
    target_compile_definitions(MessageUClient PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(MessageUClient PRIVATE ws2_32 mswsock)
endif()

# _rdrand32_step needs the rdrnd instructions on gcc and clang
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(MessageUClient PRIVATE -mrdrnd)
endif()
