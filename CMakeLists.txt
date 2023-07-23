cmake_minimum_required(VERSION 3.5)

project(DigitalSignature_libgcrypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(lgcrypt_USE_STATIC_LIBS OFF)
set(lgcrypt_USE_MULTITHREADED ON)

link_directories(/usr/lib/libgcrypt.so)

add_executable(DigitalSignature_libgcrypt main.cpp)
target_link_libraries(DigitalSignature_libgcrypt gcrypt)
