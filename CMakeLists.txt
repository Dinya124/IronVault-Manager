cmake_minimum_required(VERSION 3.31)
project(IronVault_Manager)

set(CMAKE_CXX_STANDARD 20)

add_executable(IronVault_Manager main.cpp
        CredentialVault.cpp
        CredentialVault.h)
