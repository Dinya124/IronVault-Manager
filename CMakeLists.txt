cmake_minimum_required(VERSION 3.12)
project(IronVault-Manager)

# Уберите дублирование find_package

set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL-Win64/include")


message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
# Добавьте поиск компонентов OpenSSL
find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)

if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found: ${OpenSSL_VERSION}")
    message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
else()
    message(FATAL_ERROR "OpenSSL not found at: ${OPENSSL_ROOT_DIR}")
endif()

add_executable(IronVault-Manager
        main.cpp
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
        CredentialRecord.h
)

target_include_directories(IronVault-Manager PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Подключение OpenSSL
target_link_libraries(IronVault-Manager PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(IronVault-Manager PRIVATE ws2_32 crypt32)
endif()

message(STATUS "Project configured successfully with OpenSSL")