cmake_minimum_required(VERSION 3.16)
project(CPPSpider)

set(CMAKE_CXX_STANDARD 14)
set(
    MAIN_SOURCE
    csr_socket.cpp 
    csr_socket.h
    csr_http.h
    csr_http.cpp
    cJSON.h
    cJSON.c
    csr_log.h
    csr_log.cpp
    csr_mem.h
    csr_mem.cpp
    csr_error.h
    csr_error.cpp
)

set(
    TEST_SOURCE
    main.cpp
    logger.hpp
    logger.cpp
    thread.hpp
    thread.cpp
)

# add_executable(spider get_mooc.cpp ${MAIN_SOURCE})
# add_executable(downloader dlder.cpp ${MAIN_SOURCE})
add_executable(main_test ${TEST_SOURCE})