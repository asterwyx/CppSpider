#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <cstdint>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include "cJSON.h"

#include "csr_mem.h"

#define MAX_HEADER_LEN      1024
#define MAX_HEADER_NUM      50
#define DATA_ROOT           "C:/repos/cpp/CppSpider/DataRoot/"
#define MAX_NAME_LEN        1024
#define GET_ADDR_FAILED     -1
#define BUF_SIZE            4096
#define MAX_CHUNK_SIZE      10
#define MAX_HANDLE_NUM      20

typedef struct http_ver {
    int n_major_ver;
    int n_minor_ver;
} http_ver_t;

typedef enum method {
    GET,
    POST,
    DEL
} method_t;

typedef struct response_hdr {
    http_ver_t version;
    int n_status_code;
    char description[MAX_NAME_LEN];
    char content_type[MAX_NAME_LEN];
    int n_content_len;
    cJSON *a_extra_headers = cJSON_CreateArray();
    int n_header_num = 0;
    csr::p_mbuf_t p_body_buf;
    bool parsed = false;
    bool chunked = false;
    char body_filename[MAX_NAME_LEN];
} response_hdr_t, *p_response_hdr_t;

typedef struct request_hdr {
    method_t request_method = method_t::GET;
    char hostname[MAX_NAME_LEN];
    char content_type[MAX_NAME_LEN];
    char token[MAX_NAME_LEN];
    char path[MAX_NAME_LEN];
    http_ver_t version = {1, 1};
    int n_content_len = 0;
    char cookies[MAX_HEADER_LEN];
    char* a_extra_headers[MAX_HEADER_NUM];
    int n_header_num = 0;
    char* p_body = nullptr;
} request_hdr_t, *p_request_hdr_t;

typedef struct request request_t, *p_request_t;
typedef struct session session_t, *p_session_t;

struct request {
    p_request_hdr_t req_hdr;
    p_response_hdr_t res_hdr;
    p_session_t p_session;
    struct request *next;
};

struct session {
    char hostname[MAX_NAME_LEN];
    PADDRINFOA addrinfo;
    p_request_t head = nullptr;
    p_request_t tail = nullptr;
    int n_req_num = 0;
    int n_cookie_num = 0;
    cJSON* cookie_jar = cJSON_CreateArray();
}; 

uint64_t csr_init_http();
int http_request(p_session_t p_session);
char* print_request(p_request_hdr_t p_request);
int parse_header(p_response_hdr_t p_response, char* res_str, int* n_parsed);
void dispose();
int norm_key_str(char* raw_str, char* normalized_str, int n_buf_size);
cJSON* parse_cookie_str(char* cookie_str);
int next_request(p_session_t p_session, const char* new_path, method_t new_method, const char* new_body, const char* new_body_filename);
p_session_t create_session(const char *hostname);
p_request_t create_request();
void init_session(p_session_t p_session);
void destroy_session(p_session_t *pp_session);
void destroy_request(p_request_t *pp_request);
void get_cookies(p_request_t p_request);
int check_cookie(cJSON* p_cookie_jar, cJSON* p_cookie);
void add_header(p_request_hdr_t p_request, const char* header);
void recv_handler(SOCKET socket, void *p_session);
