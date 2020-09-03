#include "csr_http.h"
#include <iostream>
#include <string>

#define CSR_WINDOWS

#include "csr_log.h"
#include "csr_mem.h"
#include "csr_socket.h"
#include "csr_thread.h"
#pragma comment(lib, "ws2_32.lib")

extern csr::p_mempool_t g_csr_mp;

using std::cerr;
using std::cout;
using std::endl;
using std::string;

uint64_t csr_init_http()
{
    csr::start_scheduler();
    return rc::SUCCESS;
}


int link_chunked(csr::p_mbuf_t *p_mbuf)
{
    csr::p_mbuf_t new_mbuf = csr::alloc_mbuf(g_csr_mp);
    auto buffer = (char *)(*p_mbuf)->data;
    char len_buf[MAX_NAME_LEN];
    uint32_t cursor = 0, end = cursor;
    while (cursor < (*p_mbuf)->n_dlength)
    {
        while (buffer[end] != '\r' && buffer[end] != '\n')
        {
            end++;
        }
        strncpy_s(len_buf, MAX_NAME_LEN, buffer + cursor, end - cursor);
        while (buffer[end] == '\r' || buffer[end] == '\n')
        {
            end++;
        }
        cursor = end;
        auto len = strtol(len_buf, nullptr, 16);
        memcpy(new_mbuf->data + new_mbuf->n_dlength, buffer + cursor, len);
        new_mbuf->n_dlength += len;
        if (len == 0)
        {
            break;
        }
        end += len;
        while (buffer[end] == '\r' || buffer[end] == '\n')
        {
            end++;
        }
        cursor = end;
    }
    csr::free_mbuf(*p_mbuf);
    *p_mbuf = new_mbuf;
    return 0;
}

thrd_ret_t API write_to_file(void *lp_res)
{
    p_response_hdr_t res = (p_response_hdr_t)lp_res;
    if (res->chunked)
    {
        link_chunked(&res->p_body_buf);
        res->n_content_len = res->p_body_buf->n_dlength;
    }
    string name(DATA_ROOT);
    name += res->body_filename;
    file_t *fp;
    fopen_s(&fp, name.c_str(), "w");
    fwrite(res->p_body_buf->data, 1, res->p_body_buf->n_dlength, fp);
    fclose(fp);
    return 0;
}

// int send_request(SOCKET SocketConn, char* RequestString)
// {
//     int n_req_len = strlen(RequestString);
//     int SentLen = 0;
//     while (SentLen < n_req_len)
//     {
//         int len = send(SocketConn, RequestString + SentLen, n_req_len - SentLen, 0);
//         if (len >= 0)
//         {
//             SentLen += len;
//         }
//         else
//         {
//             break;
//         }
//     }
//     CSR_INFO("Sent %d bytes.\n", SentLen);
//     return 0;
// }

int recv_response(SOCKET skt_conn, p_response_hdr_t p_res_got)
{
    // Here we alloc and free a buffer
    p_res_got->p_body_buf = csr::alloc_mbuf(g_csr_mp);
    int n_hdr_len = 0, len;
    char tmp_buf[BUF_SIZE];
    auto p_recv_buf = (char *)p_res_got->p_body_buf->data;
    do {
        len = recv(skt_conn, tmp_buf, BUF_SIZE, 0);
    } while (len < 0);

    if (len != 0) {
        /* First parse headers */
        p_res_got->parsed = true;
        parse_header(p_res_got, tmp_buf, &n_hdr_len);
        len -= n_hdr_len;
        memcpy(p_recv_buf, tmp_buf + n_hdr_len, len);
        p_recv_buf += len;
        p_res_got->p_body_buf->n_dlength += len;
        do {
            len = recv(skt_conn, p_recv_buf, p_res_got->p_body_buf->n_dsize - p_res_got->p_body_buf->n_dlength, 0);
            if (len == SOCKET_ERROR) {
                auto error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK) {
                    continue;
                } else {
                    CSR_ERROR("Receive error, error code: %d\n", error);
                }
            } else if (len == 0) {
                break;
            } else {
                p_recv_buf += len;
                p_res_got->p_body_buf->n_dlength += len;
            }
        } while(true);

    }
    p_res_got->p_body_buf->data[p_res_got->p_body_buf->n_dlength] = 0;
    if (n_hdr_len == 0) {
        CSR_ERROR("Receive failed.\n");
        return -1;
    } else {
        CSR_DEBUG("Socket %llu received %d bytes.\n", skt_conn, p_res_got->p_body_buf->n_dlength);
    }
    CreateThread(nullptr, 0, write_to_file, p_res_got, 0, nullptr);
    return 0;
}

void recv_handler(SOCKET socket, void *p_request)
{
    p_request_t request = (p_request_t)p_request;
    int status = recv_response(socket, request->res_hdr);
    if (status != 0) {
        CSR_ERROR("Receive response failed.\n");
    }
    get_cookies(request);
}


void dispose()
{
}

int http_request(p_session_t p_session)
{
    csr::p_task_t pTask = csr::create_task(p_session->tail, BUF_SIZE);
    pTask->p_addrinfo = p_session->addrinfo;
    pTask->f_recv_handler = recv_handler;
    char* ReqStr = print_request(p_session->tail->req_hdr);
    strcpy_s(pTask->p_send_buf, BUF_SIZE, ReqStr);
    free(ReqStr);
    return add_task(pTask);
}


inline void add_request(p_session_t p_session, p_request_t p_request) {
    p_request->p_session = p_session;
    if (p_session->n_req_num == 0) {
        p_session->head = p_request;
        p_session->tail = p_session->head;
    } else {
        p_session->tail->next = p_request;
        p_session->tail = p_request;
    }
    ++p_session->n_req_num;
}

/**
 * 用于快速生成下一个请求的工具函数
 */
int next_request(p_session_t session, const char *NewPath, method_t NewMethod, const char* NewBody, const char* NewBodyFileName)
{
    char buffer[BUF_SIZE];
    p_request_t next_req = create_request();
    next_req->req_hdr->request_method = NewMethod;
    next_req->req_hdr->n_content_len = 0;
    next_req->req_hdr->content_type[0] = 0;
    next_req->req_hdr->token[0] = 0;
    next_req->req_hdr->cookies[0] = 0;
    cJSON* KeyCookie = nullptr;
    for (int i = 0; i < session->n_cookie_num; i++)
    {
        KeyCookie = cJSON_GetArrayItem(session->cookie_jar, i);
        norm_key_str(cJSON_GetObjectItem(KeyCookie, "Key")->valuestring, buffer, BUF_SIZE);
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
    if (next_req->req_hdr->request_method == method_t::POST)
    {
        sprintf_s(next_req->req_hdr->path, MAX_NAME_LEN, "%s?csrfKey=%s", NewPath, CsrfKey);
        sprintf_s(next_req->req_hdr->content_type, MAX_NAME_LEN, "Content-Type: application/x-www-form-urlencoded");
        sprintf_s(next_req->req_hdr->token, MAX_NAME_LEN, "edu-script-token: %s", CsrfKey);
    }
    else
    {
        strcpy_s(next_req->req_hdr->path, MAX_NAME_LEN, NewPath);
    }
    if (NewBody != nullptr)
    {
        if (next_req->req_hdr->p_body == nullptr)
        {
            next_req->req_hdr->p_body = (char*)malloc(BUF_SIZE);
        }
        strcpy_s(next_req->req_hdr->p_body, BUF_SIZE, NewBody);
        next_req->req_hdr->n_content_len = strlen(next_req->req_hdr->p_body);
    }
    strcpy_s(next_req->res_hdr->body_filename, MAX_NAME_LEN, NewBodyFileName);
    next_req->res_hdr->parsed = false;
    cJSON_Delete(next_req->res_hdr->a_extra_headers);
    cJSON* cookie;
    sprintf_s(next_req->req_hdr->cookies, MAX_HEADER_LEN, "Cookie: "); // 初始化键
    for (int i = 0; i < session->n_cookie_num; i++)
    {
        cookie = cJSON_GetArrayItem(session->cookie_jar, i);
        cJSON* CookieStr = cJSON_GetObjectItem(cookie, "Raw");
        strcat_s(next_req->req_hdr->cookies, MAX_HEADER_LEN - strlen(next_req->req_hdr->cookies), CookieStr->valuestring);
        strcat_s(next_req->req_hdr->cookies, MAX_HEADER_LEN - strlen(next_req->req_hdr->cookies), "; ");
    }
    next_req->req_hdr->cookies[strlen(next_req->req_hdr->cookies) - 2] = 0;
    add_request(session, next_req);
    return 0;
}

p_session_t create_session(const char* hostname)
{
    p_session_t result = (p_session_t)malloc(sizeof(session_t));
    if (result == nullptr)
    {
        CSR_ERROR("Out of memory!\n");
        exit(EXIT_FAILURE);
    }
    strcpy_s(result->hostname, hostname);
    ADDRINFO hints;
    memset(&hints, 0, sizeof(ADDRINFO));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO::IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    int ret = getaddrinfo(hostname, "http", &hints, &result->addrinfo);
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
    init_session(result);
    return result;
}

inline void init_req_hdr(p_request_hdr_t p_req_hdr) {
    p_req_hdr->request_method = method_t::GET;
    p_req_hdr->hostname[0] = 0;
    p_req_hdr->content_type[0] = 0;
    p_req_hdr->token[0] = 0;
    p_req_hdr->path[0] = 0;
    p_req_hdr->version.n_major_ver = 1;
    p_req_hdr->version.n_minor_ver = 1;
    p_req_hdr->n_content_len = 0;
    p_req_hdr->cookies[0] = 0;
    p_req_hdr->n_header_num = 0;
    p_req_hdr->p_body = nullptr;
}

inline void init_res_hdr(p_response_hdr_t p_res_hdr) {
    p_res_hdr->description[0] = 0;
    p_res_hdr->content_type[0] = 0;
    p_res_hdr->n_content_len = 0;
    p_res_hdr->a_extra_headers = cJSON_CreateArray();
    p_res_hdr->n_header_num = 0;
    p_res_hdr->parsed = false;
    p_res_hdr->chunked = false;
    p_res_hdr->body_filename[0] = 0;
}

p_request_t create_request()
{
    p_request_t p_request = (p_request_t)malloc(sizeof(request_t));
    if (p_request == nullptr) {
        CSR_ERROR("Out of memory!\n");
        exit(EXIT_FAILURE);
    }
    p_request->next = nullptr;
    p_request->req_hdr = (p_request_hdr_t)malloc(sizeof(request_hdr_t));
    init_req_hdr(p_request->req_hdr);
    p_request->res_hdr = (p_response_hdr_t)malloc(sizeof(response_hdr_t));
    init_res_hdr(p_request->res_hdr);
    if (p_request->req_hdr == nullptr || p_request->res_hdr == nullptr) {
        CSR_ERROR("Out of memory!\n");
        exit(EXIT_FAILURE);
    }
    return p_request;
}

void init_session(p_session_t p_session)
{
    p_session->n_req_num = 0;
    p_session->cookie_jar = cJSON_CreateArray();
    p_session->n_cookie_num = 0;
    add_request(p_session, create_request());
}


void destroy_session(p_session_t* pp_session)
{
    if (*pp_session == nullptr)
    {
        return;
    }
    p_request_t cur, tmp;
    cur = (*pp_session)->head;
    for (int i = 0; i < (*pp_session)->n_req_num; ++i) {
        tmp = cur;
        cur = tmp->next;
        destroy_request(&tmp);
    }
    freeaddrinfo((*pp_session)->addrinfo);
    free(*pp_session);
    *pp_session = nullptr;
    if ((*pp_session)->cookie_jar != nullptr)
    {
        cJSON_Delete((*pp_session)->cookie_jar);
    }
}

void destroy_request(p_request_t *pp_request)
{
    for (int i = 0; i < (*pp_request)->req_hdr->n_header_num; i++)
    {
        free((*pp_request)->req_hdr->a_extra_headers[i]);
    }
    if ((*pp_request)->req_hdr->p_body != nullptr)
    {
        free((*pp_request)->req_hdr->p_body);
    }
    free((*pp_request)->req_hdr);
    cJSON_Delete((*pp_request)->res_hdr->a_extra_headers);
    free((*pp_request)->res_hdr);
    if ((*pp_request)->res_hdr->p_body_buf != nullptr)  {
        csr::free_mbuf((*pp_request)->res_hdr->p_body_buf);
    }
    *pp_request = nullptr;
}

char* print_request(p_request_hdr_t p_request)
{
    char* result = (char*)malloc(BUF_SIZE);
    int n_req_len = 0;
    switch (p_request->request_method)
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
    n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s ", p_request->path);
    n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "HTTP/%d.%d\r\n", p_request->version.n_major_ver, p_request->version.n_minor_ver);
    if (p_request->n_content_len != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "Content-Length: %d\r\n", p_request->n_content_len);
    }
    for (int i = 0; i < p_request->n_header_num; i++)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s\r\n", p_request->a_extra_headers[i]);
    }
    if (strlen(p_request->content_type) != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s\r\n", p_request->content_type);
    }
    if (strlen(p_request->token) != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s\r\n", p_request->token);
    }
    if (strlen(p_request->cookies) != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s\r\n", p_request->cookies);
    }
    n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "\r\n");
    if (p_request->p_body != nullptr && p_request->n_content_len != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s", p_request->p_body);
    }
    return result;
}

int parse_header(p_response_hdr_t p_response, char* res_str, int* n_parsed)
{
    int cursor = 5;
    int end = cursor;
    char KeyBuf[BUF_SIZE];
    char buffer[BUF_SIZE];
    while (res_str[end] != '.')
    {
        end++;
    }
    strncpy_s(buffer, BUF_SIZE, res_str + cursor, end - cursor);
    p_response->version.n_major_ver = atoi(buffer);
    cursor = ++end;
    while (res_str[end] != ' ')
    {
        end++;
    }
    strncpy_s(buffer, BUF_SIZE, res_str + cursor, end - cursor);
    p_response->version.n_minor_ver = atoi(buffer);
    cursor = ++end;
    while (res_str[end] != ' ')
    {
        end++;
    }
    strncpy_s(buffer, BUF_SIZE, res_str + cursor, end - cursor);
    p_response->n_status_code = atoi(buffer);
    cursor = ++end;
    while (res_str[end] != '\r' && res_str[end] != '\n')
    {
        end++;
    }
    strncpy_s(p_response->description, MAX_NAME_LEN, res_str + cursor, end - cursor);
    if (res_str[end + 1] == '\n')
    {
        ++end;
    }
    cursor = ++end;
    while (true)
    {
        while (res_str[end] != ':' && res_str[end] != '\r' && res_str[end] != '\n')
        {
            end++;
        }
        if (cursor == end)
        {
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
        while (res_str[end] != '\r' && res_str[end] != '\n')
        {
            end++;
        }
        strncpy_s(buffer, BUF_SIZE, res_str + cursor, end - cursor);
        buffer[end - cursor] = 0;
        cJSON* Header = cJSON_CreateObject();
        cJSON_AddStringToObject(Header, KeyBuf, buffer);
        cJSON_AddItemToArray(p_response->a_extra_headers, Header);
        norm_key_str(KeyBuf, buffer, BUF_SIZE);
        if (strcmp(buffer, "transfer-encoding") == 0) {
            norm_key_str(cJSON_GetObjectItem(Header, KeyBuf)->valuestring, buffer, BUF_SIZE);
            if (strcmp(buffer, "chunked") == 0)
            {
                p_response->chunked = true;
            }
        } else if (strcmp(buffer, "content-length") == 0) {
            norm_key_str(cJSON_GetObjectItem(Header, KeyBuf)->valuestring, buffer, BUF_SIZE);
            p_response->n_content_len = atoi(buffer);
        }
        if (res_str[end + 1] == '\n')
        {
            ++end;
        }
        cursor = ++end;
        p_response->n_header_num++;
    }
    *n_parsed = cursor;
    CSR_DEBUG("Status code: %d, Description: %s, Content-Length: %d\n", p_response->n_status_code, p_response->description, p_response->n_content_len);
    return 0;
}

int norm_key_str(char* RawStr, char* NormalizedStr, int iBufSize)
{
    int length = strlen(RawStr);
    if (iBufSize <= length)
    {
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

cJSON* parse_cookie_str(char* CookieString)
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
    strncpy_s(KeyBuf, BUF_SIZE, CookieString + cursor, end - cursor);
    cJSON_AddStringToObject(CookieResult, "Key", KeyBuf);
    cursor = ++end;
    while (end < length && CookieString[end] != ';')
    {
        end++;
    }
    strncpy_s(ValBuf, BUF_SIZE, CookieString + cursor, end - cursor);
    cJSON_AddStringToObject(CookieResult, "Value", ValBuf);
    strcat_s(KeyBuf, BUF_SIZE - strlen(KeyBuf), "=");
    strcat_s(KeyBuf, BUF_SIZE - strlen(KeyBuf), ValBuf);
    cJSON_AddStringToObject(CookieResult, "Raw", KeyBuf);
    ++end;
    cursor = ++end;
    while (end < length)
    {
        while (end < length && CookieString[end] != '=')
        {
            end++;
        }
        strncpy_s(KeyBuf, BUF_SIZE, CookieString + cursor, end - cursor);
        cursor = ++end;
        while (end < length && CookieString[end] != ';')
        {
            end++;
        }
        strncpy_s(ValBuf, BUF_SIZE, CookieString + cursor, end - cursor);
        cJSON_AddStringToObject(CookieResult, KeyBuf, ValBuf);
        ++end;
        cursor = ++end;
    }
    return CookieResult;
}

void get_cookies(p_request_t p_request)
{
    char KeyBuf[BUF_SIZE];
    cJSON* ArrayItem;
    for (int i = 0; i < p_request->res_hdr->n_header_num; i++)
    {
        ArrayItem = cJSON_GetArrayItem(p_request->res_hdr->a_extra_headers, i);
        norm_key_str(ArrayItem->child->string, KeyBuf, BUF_SIZE);
        if (strcmp(KeyBuf, "set-cookie") == 0 || strcmp(KeyBuf, "set-cookie2") == 0)
        {
            cJSON* CookieArrayItem = parse_cookie_str(ArrayItem->child->valuestring);
            int exist = check_cookie(p_request->p_session->cookie_jar, CookieArrayItem);
            if (exist == -1)
            {
                cJSON_AddItemToArray(p_request->p_session->cookie_jar, CookieArrayItem);
                p_request->p_session->n_cookie_num++;
            }
            else
            {
                cJSON_DeleteItemFromArray(p_request->p_session->cookie_jar, exist);
                cJSON_AddItemToArray(p_request->p_session->cookie_jar, CookieArrayItem);
            }
            cJSON_DeleteItemFromArray(p_request->res_hdr->a_extra_headers, i--);
            p_request->res_hdr->n_header_num--;
        }
    }
}

int check_cookie(cJSON* CookieJar, cJSON* cookie)
{
    char buffer1[BUF_SIZE], buffer2[BUF_SIZE];
    norm_key_str(cJSON_GetObjectItem(cookie, "Key")->valuestring, buffer1, BUF_SIZE);
    int CookieNum = cJSON_GetArraySize(CookieJar);
    int index = -1;
    cJSON* item;
    for (int i = 0; i < CookieNum; i++)
    {
        item = cJSON_GetArrayItem(CookieJar, i);
        norm_key_str(cJSON_GetObjectItem(item, "Key")->valuestring, buffer2, BUF_SIZE);
        if (strcmp(buffer1, buffer2) == 0)
        {
            index = i;
            break;
        }
    }
    return index;
}

void add_header(p_request_hdr_t request, const char* header)
{
    request->a_extra_headers[request->n_header_num] = (char*)malloc(strlen(header) + 1);
    strcpy_s(request->a_extra_headers[request->n_header_num++], strlen(header) + 1, header);	
}

