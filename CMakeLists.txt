cmake_minimum_required(VERSION 3.31)
project(IronVault-Manager)


set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")



add_executable(IronVault-Manager main.cpp
        MasterPasswordManager.cpp
        MasterPasswordManager.h
        PasswordGenerator.cpp
        PasswordGenerator.h
        SearchFilter.cpp
        SearchFilter.h
        SecureInputBuffer.cpp
        SecureInputBuffer.h
        DataEncryption.cpp
        DataEncryption.h
        CredentialRecord.cpp
        CredentialRecord.h)



target_include_directories(IronVault-Manager PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Теперь ищем OpenSSL
find_package(OpenSSL REQUIRED)

if(OpenSSL_FOUND)
    target_link_libraries(IronVault-Manager PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "OpenSSL found: ${OpenSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL not found at: ${OPENSSL_ROOT_DIR}")
endif()

if(WIN32)
    target_link_libraries(IronVault-Manager PRIVATE ws2_32 crypt32)
endif()

message(STATUS "Project configured successfully with OpenSSL")