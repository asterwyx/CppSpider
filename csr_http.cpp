#pragma once
#include <iostream>
#include <string>

#define WIN_NT

#include "csr_log.h"
#include "csr_mem.h"
#include "csr_http.h"
#include "csr_socket.h"
#include "csr_thread.h"
#pragma comment(lib, "ws2_32.lib")
#define CHECK_TRUNC(r1, r2) (r1 == '\r' && r2 == '\r' ? true : false)
HANDLE empty;
HANDLE full;

extern csr::p_mempool_t g_csr_mp;

using std::cerr;
using std::cout;
using std::endl;
using std::string;

/**
 * 处理爬下来的分段的数据
 */
int link_chunked(csr::p_mbuf_t &p_mbuf)
{
    csr::p_mbuf_t new_mbuf = csr::alloc_mbuf(g_csr_mp);
    byte *buffer = p_mbuf->data;
    char r1, r2;
    uint32_t cursor = 0;
    r2 = buffer[cursor++];
    bool truncated = true;
    while (cursor != p_mbuf->n_dlength)
    {
        r1 = r2;
        r2 = buffer[cursor++];
        if (CHECK_TRUNC(r1, r2))
        {
            truncated = !truncated;
            // 跳到0d0d0a序列
            r2 = buffer[cursor++]; // 读到0a;
            r1 = buffer[cursor++]; // 读到正常数据
            r2 = buffer[cursor++]; // 预读到正常数据，但是不一定是要被写入的
        }
        if (!truncated)
        {
            new_mbuf->data[new_mbuf->n_dlength++] = r1;
        }
    }
    csr::free_mbuf(p_mbuf);
    p_mbuf = new_mbuf;
    return 0;
}

thrd_ret_t API write_to_file(void *lp_res)
{
    p_response_t res = (p_response_t)lp_res;
    if (res->chunked)
    {
        link_chunked(res->p_body_buf);
        res->n_ctnt_len = res->p_body_buf->n_dlength;
    }
    string name(DATA_ROOT);
    name += res->body_filename;
    file_t *fp;
    fopen_s(&fp, name.c_str(), "w");
    fwrite(res->p_body_buf->data, 1, res->n_ctnt_len, fp);
    fclose(fp);
    return 0;
}

/**
 * 用于发送报文的工具函数
 */
int SendRequest(SOCKET SocketConn, char* RequestString)
{
    int n_req_len = strlen(RequestString);
    int SentLen = 0;
    while (SentLen < n_req_len)
    {
        int len = send(SocketConn, RequestString + SentLen, n_req_len - SentLen, 0);
        if (len >= 0)
        {
            SentLen += len;
        }
        else
        {
            break;
        }
    }
    CSR_INFO("Sent %d bytes.\n", SentLen);
    return 0;
}

/**
 * 用于接收报文的工具函数
 */
int recv_response(SOCKET skt_conn, p_response_t p_res_got)
{
    // Here we alloc and free a buffer
    p_res_got->p_body_buf = csr::alloc_mbuf(g_csr_mp);
    int n_rx_len = 0, n_hdr_len = 0, len;
    char tmp_buf[BUF_SIZE];
    auto p_recv_buf = tmp_buf;
    while (true)
    {
        len = recv(skt_conn, p_recv_buf, BUF_SIZE, 0);
        if (len <= 0)
        {
            break;
        }
        else
        {
            // parse header first
            if (!p_res_got->parsed)
            {
                p_res_got->parsed = true;
                parse_hdr(p_res_got, p_recv_buf, &n_hdr_len);
                strcpy((char *)p_res_got->p_body_buf->data, p_recv_buf + n_hdr_len);
                p_recv_buf = (char *)p_res_got->p_body_buf->data;
            }
            n_rx_len += len;
            p_recv_buf += len;
        }
    }
    p_res_got->p_body_buf->n_dlength = n_rx_len - n_hdr_len;
    p_res_got->n_ctnt_len = p_res_got->p_body_buf->n_dlength;
    p_res_got->p_body_buf->data[p_res_got->n_ctnt_len] = 0;
    if (n_rx_len == 0)
    {
        CSR_ERROR("Receive failed.\n");
        return -1;
    }
    return 0;
}

void recv_handler(SOCKET socket, LPVOID pSession)
{
    p_session_t session = (p_session_t)pSession;
    int status = recv_response(socket, session->response);
    if (status != 0) {
        CSR_ERROR("Receive response failed.\n");
    }
    GetCookies(session);
    closesocket(socket);
}
int InitWSA()
{
    InitScheduler();
    StartScheduler();
    return 0;
}

void Dispose()
{
    CloseHandle(empty);
    CloseHandle(full);
}

int HttpRequest(p_session_t session)
{
    PTASK pTask = CreateTask(session, BUF_SIZE);
    pTask->pAddrInfo = session->addrinfo;
    pTask->fRecvHandler = recv_handler;
    char* ReqStr = print_req(session->request);
    strcpy_s(pTask->aSendBuf, BUF_SIZE, ReqStr);
    free(ReqStr);
    return AddTask(pTask);
}

int NextRequest(p_session_t session, const char *NewPath, method_t NewMethod, const char* NewBody, const char* NewBodyFileName)
{
    char buffer[BUF_SIZE];
    session->request->ReqMethod = NewMethod;
    session->request->n_ctnt_len = 0;
    session->request->ctnt_type[0] = 0;
    session->request->token[0] = 0;
    session->request->cookies[0] = 0;
    // 找到认证的key
    cJSON* KeyCookie = NULL;
    for (int i = 0; i < session->n_cookie_num; i++)
    {
        KeyCookie = cJSON_GetArrayItem(session->cookie_jar, i);
        NormalizeKeyStr(cJSON_GetObjectItem(KeyCookie, "Key")->valuestring, buffer, BUF_SIZE);
        if (strcmp(buffer, "ntesstudysi") == 0)
        {
            break;
        }
    }
    if (!KeyCookie)
    {
        CSR_ERROR("Can't find the cookie.\n");
        return -1;
    }
    char* CsrfKey = cJSON_GetObjectItem(KeyCookie, "Value")->valuestring;
    if (session->request->ReqMethod == method_t::POST)
    {
        sprintf_s(session->request->path, MAX_NAME_LEN, "%s?csrfKey=%s", NewPath, CsrfKey);
        sprintf_s(session->request->ctnt_type, MAX_NAME_LEN, "Content-Type: application/x-www-form-urlencoded");
        sprintf_s(session->request->token, MAX_NAME_LEN, "edu-script-token: %s", CsrfKey);
    }
    else
    {
        strcpy_s(session->request->path, MAX_NAME_LEN, NewPath);
    }
    if (NewBody != NULL)
    {
        if (session->request->body == NULL)
        {
            session->request->body = (char*)malloc(BUF_SIZE);
        }
        strcpy_s(session->request->body, BUF_SIZE, NewBody);
        session->request->n_ctnt_len = strlen(session->request->body);
    }
    strcpy_s(session->response->body_filename, MAX_NAME_LEN, NewBodyFileName);
    session->response->parsed = false;
    cJSON_Delete(session->response->extra_hdrs);
    session->response->extra_hdrs = cJSON_CreateArray();
    session->response->n_hdr_num = 0;
    // 返回Cookie
    cJSON* cookie;
    sprintf_s(session->request->cookies, MAX_HEADER_LEN, "Cookie: "); // 初始化键
    for (int i = 0; i < session->n_cookie_num; i++)
    {
        cookie = cJSON_GetArrayItem(session->cookie_jar, i);
        cJSON* CookieStr = cJSON_GetObjectItem(cookie, "Raw");
        strcat_s(session->request->cookies, MAX_HEADER_LEN - strlen(session->request->cookies), CookieStr->valuestring);
        strcat_s(session->request->cookies, MAX_HEADER_LEN - strlen(session->request->cookies), "; ");
    }
    session->request->cookies[strlen(session->request->cookies) - 2] = 0;
    return 0;
}

p_session_t CreateSession(const char* HostName)
{
    p_session_t result = (p_session_t)malloc(sizeof(session_t));
    if (result == NULL)
    {
        CSR_ERROR("Out of memory!\n");
        exit(EXIT_FAILURE);
    }
    result->request = (p_request_t)malloc(sizeof(request_t));
    if (result->request == NULL)
    {
        CSR_ERROR("Out of memory!\n");
        exit(EXIT_FAILURE);
    }
    result->response = (p_response_t)malloc(sizeof(response_t));
    if (result->response == NULL)
    {
        CSR_ERROR("Out of memory!\n");
        exit(EXIT_FAILURE);
    }
    strcpy_s(result->request->hostname, MAX_NAME_LEN, HostName);
    ADDRINFO hints;
    memset(&hints, 0, sizeof(ADDRINFO));
    // 以下代码参考msdn和https://my.oschina.net/tigerBin/blog/884788
    // hints是希望getaddrinfo函数返回的地址链表具有哪些信息
    hints.ai_family = AF_INET; // 希望使用地址族AF_INET
    hints.ai_socktype = SOCK_STREAM; // 希望是流式套接字
    hints.ai_protocol = IPPROTO_TCP; // 希望协议是TCP
    hints.ai_flags = AI_PASSIVE; // 匹配所有IP地址
    int ret = getaddrinfo(HostName, "http", &hints, &result->addrinfo);  // 第二个参数为http时，返回的地址中会自动为我们设置好端口号80，也可以直接传入"80"
    if (ret != 0)
    {
        CSR_ERROR("Get address info failed.\n");
        switch (ret)
        {
        case WSATRY_AGAIN:
            CSR_ERROR("A temporary failure in name resolution occurred.\n");
            break;
        case WSAEINVAL:
            CSR_ERROR("An invalid value was provided for the ai_flags member of the pHints parameter.\n");
            break;
        case WSANO_RECOVERY:
            CSR_ERROR("A nonrecoverable failure in name resolution occurred.\n");
            break;
        case WSAEAFNOSUPPORT:
            CSR_ERROR("The ai_family member of the pHints parameter is not supported.\n");
            break;
        case WSA_NOT_ENOUGH_MEMORY:
            CSR_ERROR("A memory allocation failure occurred.\n");
            break;
        case WSAHOST_NOT_FOUND:
            CSR_ERROR("The name does not resolve for the supplied parameters or the pNodeName and pServiceName parameters were not provided.\n");
            break;
        case WSATYPE_NOT_FOUND:
            CSR_ERROR("The pServiceName parameter is not supported for the specified ai_socktype member of the pHints parameter.\n");
            break;
        case WSAESOCKTNOSUPPORT:
            CSR_ERROR("The ai_socktype member of the pHints parameter is not supported.\n");
            break;
        default:
            break;
        }
        exit(EXIT_FAILURE);
    }
    // 进行必要的默认初始化
    InitSession(result);
    return result;
}

void InitSession(p_session_t pSession)
{
    pSession->request->ReqMethod = method_t::GET;
    pSession->request->version = { 1, 1 };
    pSession->request->n_ctnt_len = 0;
    pSession->request->n_hdr_num = 0;
    pSession->request->cookies[0] = 0;
    pSession->request->ctnt_type[0] = 0;
    pSession->request->token[0] = 0;
    sprintf_s(pSession->request->path, MAX_NAME_LEN, "/");
    pSession->request->body = NULL;
    pSession->response->extra_hdrs = cJSON_CreateArray();
    pSession->response->n_hdr_num = 0;
    pSession->response->parsed = false;
    pSession->response->chunked = false;
    pSession->cookie_jar = cJSON_CreateArray();
    pSession->n_cookie_num = 0;
}


void DestroySession(p_session_t* session)
{
    if (*session == NULL)
    {
        return;
    }
    // free掉request
    for (int i = 0; i < (*session)->request->n_hdr_num; i++)
    {
        free((*session)->request->extra_hdrs[i]);
    }
    if ((*session)->request->body != NULL)
    {
        free((*session)->request->body);
    }
    free((*session)->request);
    // free掉response
    cJSON_Delete((*session)->response->extra_hdrs);
    free((*session)->response);
    // free掉所有cookie
    if ((*session)->cookie_jar != NULL)
    {
        cJSON_Delete((*session)->cookie_jar);
    }
    freeaddrinfo((*session)->addrinfo);
    free(*session);
    *session = NULL;
}

char* print_req(p_request_t p_req)
{
    char* result = (char*)malloc(BUF_SIZE);
    int n_req_len = 0;
    switch (p_req->ReqMethod)
    {
    case method_t::GET:
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "GET ");
        break;
    case method_t::POST:
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "POST ");
        break;
    case method_t::DEL:
        break;
    default:
        break;
    }
    n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s ", p_req->path);
    n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "HTTP/%d.%d\r\n", p_req->version.n_major_ver, p_req->version.n_minor_ver);
    if (p_req->n_ctnt_len != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "Content-Length: %d\r\n", p_req->n_ctnt_len);
    }
    for (int i = 0; i < p_req->n_hdr_num; i++)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s\r\n", p_req->extra_hdrs[i]);
    }
    if (strlen(p_req->ctnt_type) != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s\r\n", p_req->ctnt_type);
    }
    if (strlen(p_req->token) != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s\r\n", p_req->token);
    }
    if (strlen(p_req->cookies) != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s\r\n", p_req->cookies);
    }
    n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "\r\n");
    if (p_req->body != NULL && p_req->n_ctnt_len != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s", p_req->body);
    }
    return result;
}

// 为了方便，只能假设缓冲区足够大，在第一次接收的时候接收到了全部的除了主体的内容
int parse_hdr(p_response_t p_res, char* res_str, int* n_parsed)
{
    // 这个函数在解析到除了主体之外的全部内容之后成功，然后会返回解析的字节数
    int cursor = 5; // 响应行前5个字节固定是HTTP/
    int end = cursor; // 辅助游标
    char KeyBuf[BUF_SIZE];
    char buffer[BUF_SIZE];
    while (res_str[end] != '.')
    {
        end++;
    }
    strncpy_s(buffer, BUF_SIZE, res_str + cursor, end - cursor);
    p_res->version.n_major_ver = atoi(buffer);
    cursor = ++end;
    while (res_str[end] != ' ')
    {
        end++;
    }
    strncpy_s(buffer, BUF_SIZE, res_str + cursor, end - cursor);
    p_res->version.n_minor_ver = atoi(buffer);
    cursor = ++end;
    while (res_str[end] != ' ')
    {
        end++;
    }
    strncpy_s(buffer, BUF_SIZE, res_str + cursor, end - cursor);
    p_res->n_status_code = atoi(buffer);
    cursor = ++end;
    while (res_str[end] != '\r' && res_str[end] != '\n')
    {
        // 为了兼容只使用\n的服务器的报文
        end++;
    }
    // 获取描述
    strncpy_s(p_res->desc, MAX_NAME_LEN, res_str + cursor, end - cursor);
    if (res_str[end + 1] == '\n')
    {
        ++end;
    }
    cursor = ++end;
    // 下面是首部的解析，目前只能先考虑服务器是以\r\n结尾的
    // 现在已经创建了Headers数组，需要往里面添加首部
    while (true)
    {
        // 得到首部key
        while (res_str[end] != ':' && res_str[end] != '\r' && res_str[end] != '\n')
        {
            end++;
        }
        if (cursor == end)
        {
            // 结束条件
            if (res_str[end + 1] == '\n')
            {
                ++end;
            }
            cursor = ++end;
            break;
        }
        strncpy_s(KeyBuf, BUF_SIZE, res_str + cursor, end - cursor);
        KeyBuf[end - cursor] = 0;
        ++end;
        cursor = ++end;
        // 得到首部value
        while (res_str[end] != '\r' && res_str[end] != '\n')
        {
            end++;
        }
        strncpy_s(buffer, BUF_SIZE, res_str + cursor, end - cursor);
        buffer[end - cursor] = 0;
        // 创建首部键值对，添加到首部数组上
        cJSON* Header = cJSON_CreateObject();
        cJSON_AddStringToObject(Header, KeyBuf, buffer);
        cJSON_AddItemToArray(p_res->extra_hdrs, Header);
        NormalizeKeyStr(KeyBuf, buffer, BUF_SIZE);
        if (strcmp(buffer, "transfer-encoding") == 0)
        {
            NormalizeKeyStr(cJSON_GetObjectItem(Header, KeyBuf)->valuestring, buffer, BUF_SIZE);
            if (strcmp(buffer, "chunked") == 0)
            {
                p_res->chunked = true;
            }
        }
        if (res_str[end + 1] == '\n')
        {
            ++end;
        }
        cursor = ++end;
        p_res->n_hdr_num++;
    }
    // 除主体内容解析完毕
    *n_parsed = cursor;
    CSR_DEBUG("Status code: %d, Description: %s\n", p_res->n_status_code, p_res->desc);
    return 0;
}

int NormalizeKeyStr(char* RawStr, char* NormalizedStr, int iBufSize)
{
    int length = strlen(RawStr);
    if (iBufSize <= length)
    {
        // 缓冲区过小
        CSR_ERROR("NormalizeKeyStr: Buffer is too small!\n");
        return -1;
    }
    for (int i = 0; i < length; i++)
    {
        char c = RawStr[i];
        if (isalpha(c))
        {
            NormalizedStr[i] = tolower(c);
        }
        else
        {
            NormalizedStr[i] = c;
        }
    }
    NormalizedStr[length] = 0;
    return 0;
}

cJSON* ParseCookieString(char* CookieString)
{
    cJSON* CookieResult = cJSON_CreateObject();
    char ValBuf[BUF_SIZE];
    char KeyBuf[BUF_SIZE];
    int cursor = 0, end = 0;
    int length = strlen(CookieString);
    while (end < length && CookieString[end] != '=')
    {
        end++;
    }
    strncpy_s(KeyBuf, BUF_SIZE, CookieString + cursor, end - cursor); // strncpy_s会自动添加\0，它要求缓冲区的大小严格比被拷贝的字符数多
    // 拿到了cookie的key
    cJSON_AddStringToObject(CookieResult, "Key", KeyBuf);
    cursor = ++end; // 跳过等号
    while (end < length && CookieString[end] != ';')
    {
        end++;
    }
    strncpy_s(ValBuf, BUF_SIZE, CookieString + cursor, end - cursor);
    // 拿到了cookie的value
    cJSON_AddStringToObject(CookieResult, "Value", ValBuf);
    strcat_s(KeyBuf, BUF_SIZE - strlen(KeyBuf), "=");
    strcat_s(KeyBuf, BUF_SIZE - strlen(KeyBuf), ValBuf);
    cJSON_AddStringToObject(CookieResult, "Raw", KeyBuf);
    // 下面开始拷贝cookie的一些属性
    ++end;
    cursor = ++end; // 跳过空格和;
    while (end < length)
    {
        while (end < length && CookieString[end] != '=')
        {
            end++;
        }
        strncpy_s(KeyBuf, BUF_SIZE, CookieString + cursor, end - cursor);
        // 拿到了cookie属性的key
        cursor = ++end; // 跳过等号
        while (end < length && CookieString[end] != ';')
        {
            end++;
        }
        strncpy_s(ValBuf, BUF_SIZE, CookieString + cursor, end - cursor);
        // 拿到了cookie属性的value
        cJSON_AddStringToObject(CookieResult, KeyBuf, ValBuf);
        ++end;
        cursor = ++end; // 跳过空格和;
    }
    return CookieResult;
}

void GetCookies(p_session_t session)
{
    char KeyBuf[BUF_SIZE];
    // 解析首部，填充特殊首部信息，生成Cookie数组
    cJSON* ArrayItem;
    for (int i = 0; i < session->response->n_hdr_num; i++)
    {
        ArrayItem = cJSON_GetArrayItem(session->response->extra_hdrs, i);
        NormalizeKeyStr(ArrayItem->child->string, KeyBuf, BUF_SIZE);
        if (strcmp(KeyBuf, "set-cookie") == 0 || strcmp(KeyBuf, "set-cookie2") == 0)
        {
            // 找到一个cookie
            cJSON* CookieArrayItem = ParseCookieString(ArrayItem->child->valuestring);
            int exist = CheckCookie(session->cookie_jar, CookieArrayItem);
            if (exist == -1)
            {
                // 不存在这个cookie
                cJSON_AddItemToArray(session->cookie_jar, CookieArrayItem);
                session->n_cookie_num++;
            }
            else
            {
                // 存在这个cookie，更新这个cookie
                cJSON_DeleteItemFromArray(session->cookie_jar, exist);
                cJSON_AddItemToArray(session->cookie_jar, CookieArrayItem);
            }
            cJSON_DeleteItemFromArray(session->response->extra_hdrs, i--);
            session->response->n_hdr_num--;
        }
    }
}

int CheckCookie(cJSON* CookieJar, cJSON* cookie)
{
    char buffer1[BUF_SIZE], buffer2[BUF_SIZE];
    NormalizeKeyStr(cJSON_GetObjectItem(cookie, "Key")->valuestring, buffer1, BUF_SIZE);
    int CookieNum = cJSON_GetArraySize(CookieJar);
    int index = -1;
    cJSON* item;
    for (int i = 0; i < CookieNum; i++)
    {
        item = cJSON_GetArrayItem(CookieJar, i);
        NormalizeKeyStr(cJSON_GetObjectItem(item, "Key")->valuestring, buffer2, BUF_SIZE);
        if (strcmp(buffer1, buffer2) == 0)
        {
            index = i;
            break;
        }
    }
    return index;
}

void AddHeader(p_request_t request, const char* header)
{
    request->extra_hdrs[request->n_hdr_num] = (char*)malloc(strlen(header) + 1);
    strcpy_s(request->extra_hdrs[request->n_hdr_num++], strlen(header) + 1, header);	
}

