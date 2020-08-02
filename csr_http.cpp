#include "csr_http.h"
#include <iostream>
#include <string>

#define CSR_WINDOWS

#include "csr_log.h"
#include "csr_mem.h"
#include "csr_socket.h"
#include "csr_thread.h"
#pragma comment(lib, "ws2_32.lib")
#define CHECK_TRUNC(r1, r2) ((r1 == '\r' && r2 == '\n') ? true : false)

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
    byte *buffer = (*p_mbuf)->data;
    char r1, r2;
    uint32_t cursor = 0;
    r2 = buffer[cursor++];
    bool truncated = true;
    while (cursor != (*p_mbuf)->n_dlength)
    {
        r1 = r2;
        r2 = buffer[cursor++];
        if (CHECK_TRUNC(r1, r2))
        {
            truncated = !truncated;
            r2 = buffer[cursor++];
            r1 = buffer[cursor++];
            r2 = buffer[cursor++];
        }
        if (!truncated)
        {
            new_mbuf->data[new_mbuf->n_dlength++] = r1;
        }
    }
    csr::free_mbuf(*p_mbuf);
    *p_mbuf = new_mbuf;
    return 0;
}

thrd_ret_t API write_to_file(void *lp_res)
{
    p_response_t res = (p_response_t)lp_res;
    if (res->chunked)
    {
        link_chunked(&res->p_body_buf);
        res->n_content_len = res->p_body_buf->n_dlength;
    }
    string name(DATA_ROOT);
    name += res->body_filename;
    file_t *fp;
    fopen_s(&fp, name.c_str(), "w");
    fwrite(res->p_body_buf->data, 1, res->n_content_len, fp);
    fclose(fp);
    return 0;
}

int send_request(SOCKET SocketConn, char* RequestString)
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

int recv_response(SOCKET skt_conn, p_response_t p_res_got)
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
        p_res_got->parsed = true;
        parse_header(p_res_got, tmp_buf, &n_hdr_len);
        len -= n_hdr_len;
        memcpy(p_recv_buf, tmp_buf + n_hdr_len, len);
        do {
            if (len == SOCKET_ERROR) {
                auto error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK) {
                    // Actually, here we need to rewait.
                    // TODO
                    continue;
                } else {
                    CSR_ERROR("Receive error, error code: %d\n", error);
                }
            } else if (len == 0) {
                break;
            } else {
                p_recv_buf += len;
                p_res_got->p_body_buf->n_dlength += len;
                len = recv(skt_conn, p_recv_buf, p_res_got->p_body_buf->n_dsize - p_res_got->p_body_buf->n_dlength, 0);
            }
        } while(true);

    }
    p_res_got->p_body_buf->data[p_res_got->p_body_buf->n_dlength] = 0;
    if (n_hdr_len == 0) {
        CSR_ERROR("Receive failed.\n");
        return -1;
    } else {
        CSR_DEBUG("Socket %llu received %d bytes.", skt_conn, p_res_got->p_body_buf->n_dlength);
    }
    CreateThread(nullptr, 0, write_to_file, p_res_got, 0, nullptr);
    return 0;
}

void recv_handler(SOCKET socket, void *p_session)
{
    p_session_t session = (p_session_t)p_session;
    int status = recv_response(socket, session->response);
    if (status != 0) {
        CSR_ERROR("Receive response failed.\n");
    }
    get_cookies(session);
    closesocket(socket);
}


void dispose()
{
}

int http_request(p_session_t p_session)
{
    csr::p_task_t pTask = csr::create_task(p_session, BUF_SIZE);
    pTask->p_addrinfo = p_session->addrinfo;
    pTask->f_recv_handler = recv_handler;
    char* ReqStr = print_request(p_session->request);
    strcpy_s(pTask->p_send_buf, BUF_SIZE, ReqStr);
    free(ReqStr);
    return add_task(pTask);
}

int next_request(p_session_t session, const char *NewPath, method_t NewMethod, const char* NewBody, const char* NewBodyFileName)
{
    char buffer[BUF_SIZE];
    session->request->request_method = NewMethod;
    session->request->n_content_len = 0;
    session->request->content_type[0] = 0;
    session->request->token[0] = 0;
    session->request->cookies[0] = 0;
    cJSON* KeyCookie = NULL;
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
    if (session->request->request_method == method_t::POST)
    {
        sprintf_s(session->request->path, MAX_NAME_LEN, "%s?csrfKey=%s", NewPath, CsrfKey);
        sprintf_s(session->request->content_type, MAX_NAME_LEN, "Content-Type: application/x-www-form-urlencoded");
        sprintf_s(session->request->token, MAX_NAME_LEN, "edu-script-token: %s", CsrfKey);
    }
    else
    {
        strcpy_s(session->request->path, MAX_NAME_LEN, NewPath);
    }
    if (NewBody != NULL)
    {
        if (session->request->p_body == NULL)
        {
            session->request->p_body = (char*)malloc(BUF_SIZE);
        }
        strcpy_s(session->request->p_body, BUF_SIZE, NewBody);
        session->request->n_content_len = strlen(session->request->p_body);
    }
    strcpy_s(session->response->body_filename, MAX_NAME_LEN, NewBodyFileName);
    session->response->parsed = false;
    cJSON_Delete(session->response->a_extra_headers);
    session->response->a_extra_headers = cJSON_CreateArray();
    session->response->n_header_num = 0;
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

p_session_t create_session(const char* hostname)
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
    strcpy_s(result->request->hostname, MAX_NAME_LEN, hostname);
    ADDRINFO hints;
    memset(&hints, 0, sizeof(ADDRINFO));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
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

void init_session(p_session_t p_session)
{
    p_session->request->request_method = method_t::GET;
    p_session->request->version = { 1, 1 };
    p_session->request->n_content_len = 0;
    p_session->request->n_header_num = 0;
    p_session->request->cookies[0] = 0;
    p_session->request->content_type[0] = 0;
    p_session->request->token[0] = 0;
    sprintf_s(p_session->request->path, MAX_NAME_LEN, "/");
    p_session->request->p_body = NULL;
    p_session->response->a_extra_headers = cJSON_CreateArray();
    p_session->response->n_header_num = 0;
    p_session->response->n_content_len = 0;
    p_session->response->parsed = false;
    p_session->response->chunked = false;
    p_session->cookie_jar = cJSON_CreateArray();
    p_session->n_cookie_num = 0;
}


void destroy_session(p_session_t* pp_session)
{
    if (*pp_session == NULL)
    {
        return;
    }
    for (int i = 0; i < (*pp_session)->request->n_header_num; i++)
    {
        free((*pp_session)->request->a_extra_headers[i]);
    }
    if ((*pp_session)->request->p_body != NULL)
    {
        free((*pp_session)->request->p_body);
    }
    free((*pp_session)->request);
    cJSON_Delete((*pp_session)->response->a_extra_headers);
    free((*pp_session)->response);
    if ((*pp_session)->cookie_jar != NULL)
    {
        cJSON_Delete((*pp_session)->cookie_jar);
    }
    freeaddrinfo((*pp_session)->addrinfo);
    free(*pp_session);
    *pp_session = NULL;
}

char* print_request(p_request_t p_request)
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
    if (p_request->p_body != NULL && p_request->n_content_len != 0)
    {
        n_req_len += sprintf_s(result + n_req_len, BUF_SIZE - n_req_len, "%s", p_request->p_body);
    }
    return result;
}

int parse_header(p_response_t p_response, char* res_str, int* n_parsed)
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

void get_cookies(p_session_t session)
{
    char KeyBuf[BUF_SIZE];
    cJSON* ArrayItem;
    for (int i = 0; i < session->response->n_header_num; i++)
    {
        ArrayItem = cJSON_GetArrayItem(session->response->a_extra_headers, i);
        norm_key_str(ArrayItem->child->string, KeyBuf, BUF_SIZE);
        if (strcmp(KeyBuf, "set-cookie") == 0 || strcmp(KeyBuf, "set-cookie2") == 0)
        {
            cJSON* CookieArrayItem = parse_cookie_str(ArrayItem->child->valuestring);
            int exist = check_cookie(session->cookie_jar, CookieArrayItem);
            if (exist == -1)
            {
                cJSON_AddItemToArray(session->cookie_jar, CookieArrayItem);
                session->n_cookie_num++;
            }
            else
            {
                cJSON_DeleteItemFromArray(session->cookie_jar, exist);
                cJSON_AddItemToArray(session->cookie_jar, CookieArrayItem);
            }
            cJSON_DeleteItemFromArray(session->response->a_extra_headers, i--);
            session->response->n_header_num--;
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

void add_header(p_request_t request, const char* header)
{
    request->a_extra_headers[request->n_header_num] = (char*)malloc(strlen(header) + 1);
    strcpy_s(request->a_extra_headers[request->n_header_num++], strlen(header) + 1, header);	
}

