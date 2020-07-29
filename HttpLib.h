#pragma once
#ifndef _HTTP_H
#define _HTTP_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include "cJSON.h"
#define MAX_HEADER_LEN      1024
#define MAX_HEADER_NUM      50
#define DATA_ROOT           "../../DataRoot/"
#define MAX_NAME_LEN        1024
#define GET_ADDR_FAILED     -1
#define BUF_SIZE            4096
#define MAX_CHUNK_SIZE      10
#define MAX_HANDLE_NUM      20
extern HANDLE empty;
extern HANDLE full;

typedef struct ThreadArgs
{
    char* FileName;
} THREADARGS, * PTHREADARGS;

typedef struct HttpVersion {
    int iMajorVersion;
    int iMinorVersion;
} HTTP_VERSION;

typedef enum class method {
    GET,
    POST,
    DEL
} METHOD;

typedef struct response {
    HTTP_VERSION version;
    int iStatusCode;
    char description[MAX_NAME_LEN];
    char ContentType[MAX_NAME_LEN];
    int iContentLen;
    cJSON* ExtraHeaders = cJSON_CreateArray();
    int HeaderNum = 0;
    char body[BUF_SIZE + 1];
    bool parsed = false;
    bool chunked = false;
    char BodyFileName[MAX_NAME_LEN];
} RESPONSE, *PRESPONSE;

typedef struct request {
    METHOD ReqMethod = METHOD::GET; // 方法，默认为GET
    char HostName[MAX_NAME_LEN]; // 主机名
    char ContentType[MAX_NAME_LEN];
    char token[MAX_NAME_LEN];
    char path[MAX_NAME_LEN];  // 请求路径
    HTTP_VERSION version = {1, 1}; // Http版本，默认使用1.1
    int iContentLen = 0; // 主体长度
    char cookies[MAX_HEADER_LEN];
    char* ExtraHeaders[MAX_HEADER_NUM];
    int HeaderNum = 0;
    char* body = NULL; // 默认是GET方法，主体为空
} REQUEST, *PREQUEST;


/**
 * 现在我们需要抽象出session这个概念来控制整个过程的爬取
 */
typedef struct Session {
    PADDRINFOA AddrInfo;
    PREQUEST request;
    PRESPONSE response;
    int CookieNum = 0;
    cJSON* CookieJar = cJSON_CreateArray();
} SESSION, * PSESSION;


int InitWSA();
int HttpRequest(PSESSION session); // 这个函数唯一做的事就是发送和接收请求，不做其它事情
char* PrintRequest(PREQUEST pRequest);
int ParseResponse(PRESPONSE pResponse, char* ResStr, int* ParsedLen);
void Dispose();
//void DisposeOfResponse(PRESPONSE pResponse);
int NormalizeKeyStr(char* RawStr, char* NormalizedStr, int iBufSize);
cJSON* ParseCookieString(char* CookieString);
int NextRequest(PSESSION session, const char* NewPath, METHOD NewMethod, const char* NewBody, const char* NewBodyFileName);
PSESSION CreateSession(const char *HostName);
void InitSession(PSESSION pSession);
void DestroySession(PSESSION* session);
void GetCookies(PSESSION session);
int CheckCookie(cJSON* CookieJar, cJSON* cookie);
void AddHeader(PREQUEST request, const char* header);
void RecvHandler(SOCKET socket, LPVOID pSession);

#endif // !_HTTP_H
