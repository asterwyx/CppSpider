cmake_minimum_required(VERSION 3.16)
project(CPPSpider)

set(CMAKE_CXX_STANDARD 14)
set(SRC GetMooc.cpp SocketClient.cpp SocketClient.h HttpLib.h HttpLib.cpp cJSON.h cJSON.c)

add_executable(spider ${SRC})
add_executable(main main.cpp)