#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
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
extern HANDLE empty;
extern HANDLE full;

typedef struct thrd_args
{
    char *filename;
} thrd_args_t, *p_thrd_args_t;

typedef struct http_ver {
    int n_major_ver;
    int n_minor_ver;
} http_ver_t;

typedef enum method {
    GET,
    POST,
    DEL
} method_t;

typedef struct response {
    http_ver_t version;
    int n_status_code;
    char desc[MAX_NAME_LEN];
    char ctnt_type[MAX_NAME_LEN];
    int n_ctnt_len;
    cJSON *extra_hdrs = cJSON_CreateArray();
    int n_hdr_num = 0;
    csr::p_mbuf_t p_body_buf;
    bool parsed = false;
    bool chunked = false;
    char body_filename[MAX_NAME_LEN];
} response_t, *p_response_t;

typedef struct request {
    method_t ReqMethod = method_t::GET; // 方法，默认为GET
    char hostname[MAX_NAME_LEN]; // 主机名
    char ctnt_type[MAX_NAME_LEN];
    char token[MAX_NAME_LEN];
    char path[MAX_NAME_LEN];  // 请求路径
    http_ver_t version = {1, 1}; // Http版本，默认使用1.1
    int n_ctnt_len = 0; // 主体长度
    char cookies[MAX_HEADER_LEN];
    char* extra_hdrs[MAX_HEADER_NUM];
    int n_hdr_num = 0;
    char* body = NULL; // 默认是GET方法，主体为空
} request_t, *p_request_t;


/**
 * 现在我们需要抽象出session这个概念来控制整个过程的爬取
 */
typedef struct session {
    PADDRINFOA addrinfo;
    p_request_t request;
    p_response_t response;
    int n_cookie_num = 0;
    cJSON* cookie_jar = cJSON_CreateArray();
} session_t, * p_session_t;


int InitWSA();
int HttpRequest(p_session_t session);
char* print_req(p_request_t p_req);
int parse_hdr(p_response_t pResponse, char* ResStr, int* ParsedLen);
void Dispose();
//void DisposeOfResponse(PRESPONSE pResponse);
int NormalizeKeyStr(char* RawStr, char* NormalizedStr, int iBufSize);
cJSON* ParseCookieString(char* CookieString);
int NextRequest(p_session_t session, const char* NewPath, method_t NewMethod, const char* NewBody, const char* NewBodyFileName);
p_session_t CreateSession(const char *HostName);
void InitSession(p_session_t pSession);
void DestroySession(p_session_t* session);
void GetCookies(p_session_t session);
int CheckCookie(cJSON* CookieJar, cJSON* cookie);
void AddHeader(p_request_t request, const char* header);
void recv_handler(SOCKET socket, LPVOID pSession);
