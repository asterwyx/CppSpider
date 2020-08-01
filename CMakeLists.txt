cmake_minimum_required(VERSION 3.16)
project(CPPSpider)

set(CMAKE_CXX_STANDARD 14)
set(
    MAIN_SOURCE
    get_mooc.cpp 
    csr_socket.cpp 
    csr_socket.h
    csr_http.h
    csr_http.cpp
    cJSON.h
    cJSON.c
    csr_log.h
    csr_log.cpp
)

set(
    TEST_SOURCE
    main.cpp
    csr_log.h
    csr_log.cpp
)


add_executable(spider ${MAIN_SOURCE})
add_executable(main_test ${TEST_SOURCE})