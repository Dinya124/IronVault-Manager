cmake_minimum_required(VERSION 3.31)
project(IronVault_Manager)

set(CMAKE_CXX_STANDARD 20)

add_executable(IronVault_Manager main.cpp
        MasterPasswordManager.cpp
        MasterPasswordManager.h)

find_package(OpenSSL CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
add_executable(IronVault_Manager main.cpp
        PasswordGenerator.cpp
        PasswordGenerator.h)



add_executable(IronVault_Manager main.cpp
        SearchFilter.cpp
        SearchFilter.h)
add_executable(IronVault_Manager main.cpp
        SecureInputBuffer.cpp
        SecureInputBuffer.h)
add_executable(IronVault_Manager main.cpp
        "CredentialRecord .cpp"
        "CredentialRecord .h")
