cmake_minimum_required(VERSION 3.16)
project(CPPSpider)

set(CMAKE_CXX_STANDARD 14)

add_executable(CPPSpider main.cpp SocketClient.cpp SocketClient.h)