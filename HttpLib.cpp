#pragma once
#include "HttpLib.h"
#include "SocketClient.h"
#include <iostream>
#include <string>
#include "log.h"
#pragma comment(lib, "ws2_32.lib")
#define CHECK_TRUNC(r1, r2) (r1 == '\r' && r2 == '\r' ? true : false)
HANDLE empty;
HANDLE full;

using std::cerr;
using std::cout;
using std::endl;
using std::string;

/**
 * 处理爬下来的分段的数据
 */
DWORD WINAPI LinkChunked(LPVOID lpArgs)
{
    PTHREADARGS args = (PTHREADARGS)lpArgs;
    char buffer[BUF_SIZE];
    char source[MAX_NAME_LEN];
    char tmp[MAX_NAME_LEN];
    // filename只是名字，不包含路径
    sprintf_s(source, MAX_NAME_LEN, "%s%s", DATA_ROOT, args->FileName);
    FILE* raw = fopen(source, "rb"); // 分块传输是以字节为单位计算的，故要使用二进制流的方式打开
    sprintf_s(tmp, MAX_NAME_LEN, "%sout_%s", DATA_ROOT, args->FileName);
    FILE* out = fopen(tmp, "wb");
    int iBufSize= 0; // 使用缓冲区减少IO负担
    char r1, r2;
    r2 = fgetc(raw);
    bool truncated = true;
    while (r2 != EOF)
    {
        r1 = r2;
        r2 = fgetc(raw);
        if (CHECK_TRUNC(r1, r2))
        {
            truncated = !truncated;
            // 跳到0d0d0a序列
            r2 = fgetc(raw); // 读到0a;
            r1 = fgetc(raw); // 读到正常数据
            r2 = fgetc(raw); // 预读到正常数据，但是不一定是要被写入的
        }
        if (!truncated)
        {
            // 该字符要被写入
            if (iBufSize >= BUF_SIZE)
            {
                // 写入文件，清空缓冲区
                fwrite(buffer, 1, iBufSize, out);
                iBufSize = 0;
            }
            // 缓冲区未满，还可用
            buffer[iBufSize++] = r1;
        }
    }
    // 将最后的内容写入，flush
    fwrite(buffer, 1, iBufSize, out);
    // 关闭文件
    fclose(raw);
    remove(source);
    fclose(out);
    rename(tmp, source);
    return 0;
}

DWORD
WINAPI
WriteToFile(LPVOID lpResponse)
{
    PRESPONSE response = (PRESPONSE)lpResponse;
    string name(DATA_ROOT);
    char FileName[MAX_NAME_LEN];
    int WrittenLen = sprintf_s(FileName, MAX_NAME_LEN, DATA_ROOT);
    sprintf_s(FileName + WrittenLen, MAX_NAME_LEN - WrittenLen, response->BodyFileName);
    FILE* fp;
    fopen_s(&fp, FileName, "w");
    sprintf_s(FileName, MAX_NAME_LEN, "%s", response->BodyFileName);
    while (true)
    {
        WaitForSingleObject(full, INFINITE);
        if (strlen(response->body) == 0)
        {
            ReleaseSemaphore(empty, 1, NULL);
            break;
        }
        else
        {
            fputs(response->body , fp);
        }
        ReleaseSemaphore(empty, 1, NULL);
    }
    fclose(fp);
    // 处理分块的文件
    if (response->chunked)
    {
        THREADARGS args;
        args.FileName = FileName;
        HANDLE hThread = CreateThread(NULL, 0, LinkChunked, &args, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
    }
    return 0;
}

/**
 * 用于发送报文的工具函数
 */
int SendRequest(SOCKET SocketConn, char* RequestString)
{
    int ReqLen = strlen(RequestString);
    int SentLen = 0;
    while (SentLen < ReqLen)
    {
        int len = send(SocketConn, RequestString + SentLen, ReqLen - SentLen, 0);
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
int RecvResponse(SOCKET SocketConn, PRESPONSE pResponseGot)
{
    HANDLE thread = NULL;
    empty = CreateSemaphore(NULL, 1, 1, "empty");
    full = CreateSemaphore(NULL, 0, 1, "full");
    char RecvBuf[BUF_SIZE];
    int RecvLen = 0;
    int iParsedLen;
    while (true)
    {
        int len = recv(SocketConn, RecvBuf, BUF_SIZE, 0);
        if (len <= 0)
        {
            if (RecvLen == 0)
            {
                continue;
            }
            WaitForSingleObject(empty, INFINITE);
            pResponseGot->body[0] = 0;
            ReleaseSemaphore(full, 1, NULL);
            break;
        }
        else
        {
            RecvLen += len;
            // 拷贝到缓冲区
            if (pResponseGot->parsed)
            {
                WaitForSingleObject(empty, INFINITE);
                strncpy_s(pResponseGot->body, BUF_SIZE + 1, RecvBuf, len);
                // 为了看效果，先让buffer稍微大一点
                pResponseGot->body[len] = 0;
                ReleaseSemaphore(full, 1, NULL);
            }
            else
            {
                pResponseGot->parsed = true;
                ParseResponse(pResponseGot, RecvBuf, &iParsedLen);
                // 打印响应头部
                CSR_DEBUG("Status code: %d, Description: %s\n", pResponseGot->iStatusCode, pResponseGot->description);
                thread = CreateThread(NULL, 0, WriteToFile, pResponseGot, 0, NULL);
                WaitForSingleObject(empty, INFINITE);
                strncpy_s(pResponseGot->body, BUF_SIZE, RecvBuf + iParsedLen, len - iParsedLen);
                pResponseGot->body[len - iParsedLen] = 0;
                ReleaseSemaphore(full, 1, NULL);
            }
        }
    }
    if (RecvLen == 0)
    {
        CSR_ERROR("Receive failed.\n");
        return -1;
    }
    WaitForSingleObject(thread, INFINITE);
    pResponseGot->iContentLen = RecvLen - iParsedLen;
    return 0;
}

void RecvHandler(SOCKET socket, LPVOID pSession)
{
    PSESSION session = (PSESSION)pSession;
    int status = RecvResponse(socket, session->response);
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

int HttpRequest(PSESSION session)
{
    PTASK pTask = CreateTask(session, BUF_SIZE);
    pTask->pAddrInfo = session->AddrInfo;
    pTask->fRecvHandler = RecvHandler;
    char* ReqStr = PrintRequest(session->request);
    strcpy_s(pTask->aSendBuf, BUF_SIZE, ReqStr);
    free(ReqStr);
    return AddTask(pTask);
}

int NextRequest(PSESSION session, const char *NewPath, METHOD NewMethod, const char* NewBody, const char* NewBodyFileName)
{
    char buffer[BUF_SIZE];
    session->request->ReqMethod = NewMethod;
    session->request->iContentLen = 0;
    session->request->ContentType[0] = 0;
    session->request->token[0] = 0;
    session->request->cookies[0] = 0;
    // 找到认证的key
    cJSON* KeyCookie = NULL;
    for (int i = 0; i < session->CookieNum; i++)
    {
        KeyCookie = cJSON_GetArrayItem(session->CookieJar, i);
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
    if (session->request->ReqMethod == METHOD::POST)
    {
        sprintf_s(session->request->path, MAX_NAME_LEN, "%s?csrfKey=%s", NewPath, CsrfKey);
        sprintf_s(session->request->ContentType, MAX_NAME_LEN, "Content-Type: application/x-www-form-urlencoded");
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
        session->request->iContentLen = strlen(session->request->body);
    }
    strcpy_s(session->response->BodyFileName, MAX_NAME_LEN, NewBodyFileName);
    session->response->parsed = false;
    cJSON_Delete(session->response->ExtraHeaders);
    session->response->ExtraHeaders = cJSON_CreateArray();
    session->response->HeaderNum = 0;
    // 返回Cookie
    cJSON* cookie;
    sprintf_s(session->request->cookies, MAX_HEADER_LEN, "Cookie: "); // 初始化键
    for (int i = 0; i < session->CookieNum; i++)
    {
        cookie = cJSON_GetArrayItem(session->CookieJar, i);
        cJSON* CookieStr = cJSON_GetObjectItem(cookie, "Raw");
        strcat_s(session->request->cookies, MAX_HEADER_LEN - strlen(session->request->cookies), CookieStr->valuestring);
        strcat_s(session->request->cookies, MAX_HEADER_LEN - strlen(session->request->cookies), "; ");
    }
    session->request->cookies[strlen(session->request->cookies) - 2] = 0;
    return 0;
}

PSESSION CreateSession(const char* HostName)
{
    PSESSION result = (PSESSION)malloc(sizeof(SESSION));
    if (result == NULL)
    {
        CSR_ERROR("Out of memory!\n");
        exit(EXIT_FAILURE);
    }
    result->request = (PREQUEST)malloc(sizeof(REQUEST));
    if (result->request == NULL)
    {
        CSR_ERROR("Out of memory!\n");
        exit(EXIT_FAILURE);
    }
    result->response = (PRESPONSE)malloc(sizeof(RESPONSE));
    if (result->response == NULL)
    {
        CSR_ERROR("Out of memory!\n");
        exit(EXIT_FAILURE);
    }
    strcpy_s(result->request->HostName, MAX_NAME_LEN, HostName);
    ADDRINFO hints;
    memset(&hints, 0, sizeof(ADDRINFO));
    // 以下代码参考msdn和https://my.oschina.net/tigerBin/blog/884788
    // hints是希望getaddrinfo函数返回的地址链表具有哪些信息
    hints.ai_family = AF_INET; // 希望使用地址族AF_INET
    hints.ai_socktype = SOCK_STREAM; // 希望是流式套接字
    hints.ai_protocol = IPPROTO_TCP; // 希望协议是TCP
    hints.ai_flags = AI_PASSIVE; // 匹配所有IP地址
    int ret = getaddrinfo(HostName, "http", &hints, &result->AddrInfo);  // 第二个参数为http时，返回的地址中会自动为我们设置好端口号80，也可以直接传入"80"
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

void InitSession(PSESSION pSession)
{
    pSession->request->ReqMethod = METHOD::GET;
    pSession->request->version = { 1, 1 };
    pSession->request->iContentLen = 0;
    pSession->request->HeaderNum = 0;
    pSession->request->cookies[0] = 0;
    pSession->request->ContentType[0] = 0;
    pSession->request->token[0] = 0;
    sprintf_s(pSession->request->path, MAX_NAME_LEN, "/");
    pSession->request->body = NULL;
    pSession->response->ExtraHeaders = cJSON_CreateArray();
    pSession->response->HeaderNum = 0;
    pSession->response->parsed = false;
    pSession->response->chunked = false;
    pSession->CookieJar = cJSON_CreateArray();
    pSession->CookieNum = 0;
}


void DestroySession(PSESSION* session)
{
    if (*session == NULL)
    {
        return;
    }
    // free掉request
    for (int i = 0; i < (*session)->request->HeaderNum; i++)
    {
        free((*session)->request->ExtraHeaders[i]);
    }
    if ((*session)->request->body != NULL)
    {
        free((*session)->request->body);
    }
    free((*session)->request);
    // free掉response
    cJSON_Delete((*session)->response->ExtraHeaders);
    free((*session)->response);
    // free掉所有cookie
    if ((*session)->CookieJar != NULL)
    {
        cJSON_Delete((*session)->CookieJar);
    }
    freeaddrinfo((*session)->AddrInfo);
    free(*session);
    *session = NULL;
}

char* PrintRequest(PREQUEST pRequest)
{
    char* result = (char*)malloc(BUF_SIZE);
    int ReqLen = 0;
    switch (pRequest->ReqMethod)
    {
    case METHOD::GET:
        ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "GET ");
        break;
    case METHOD::POST:
        ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "POST ");
        break;
    case METHOD::DEL:
        break;
    default:
        break;
    }
    ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "%s ", pRequest->path);
    ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "HTTP/%d.%d\r\n", pRequest->version.iMajorVersion, pRequest->version.iMinorVersion);
    if (pRequest->iContentLen != 0)
    {
        ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "Content-Length: %d\r\n", pRequest->iContentLen);
    }
    for (int i = 0; i < pRequest->HeaderNum; i++)
    {
        ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "%s\r\n", pRequest->ExtraHeaders[i]);
    }
    if (strlen(pRequest->ContentType) != 0)
    {
        ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "%s\r\n", pRequest->ContentType);
    }
    if (strlen(pRequest->token) != 0)
    {
        ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "%s\r\n", pRequest->token);
    }
    if (strlen(pRequest->cookies) != 0)
    {
        ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "%s\r\n", pRequest->cookies);
    }
    ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "\r\n");
    if (pRequest->body != NULL && pRequest->iContentLen != 0)
    {
        ReqLen += sprintf_s(result + ReqLen, BUF_SIZE - ReqLen, "%s", pRequest->body);
    }
    return result;
}

// 为了方便，只能假设缓冲区足够大，在第一次接收的时候接收到了全部的除了主体的内容
int ParseResponse(PRESPONSE pResponse, char* ResStr, int* ParsedLen)
{
    // 这个函数在解析到除了主体之外的全部内容之后成功，然后会返回解析的字节数
    int cursor = 5; // 响应行前5个字节固定是HTTP/
    int end = cursor; // 辅助游标
    char KeyBuf[BUF_SIZE];
    char buffer[BUF_SIZE];
    while (ResStr[end] != '.')
    {
        end++;
    }
    strncpy_s(buffer, BUF_SIZE, ResStr + cursor, end - cursor);
    pResponse->version.iMajorVersion = atoi(buffer);
    cursor = ++end;
    while (ResStr[end] != ' ')
    {
        end++;
    }
    strncpy_s(buffer, BUF_SIZE, ResStr + cursor, end - cursor);
    pResponse->version.iMinorVersion = atoi(buffer);
    cursor = ++end;
    while (ResStr[end] != ' ')
    {
        end++;
    }
    strncpy_s(buffer, BUF_SIZE, ResStr + cursor, end - cursor);
    pResponse->iStatusCode = atoi(buffer);
    cursor = ++end;
    while (ResStr[end] != '\r' && ResStr[end] != '\n')
    {
        // 为了兼容只使用\n的服务器的报文
        end++;
    }
    // 获取描述
    strncpy_s(pResponse->description, MAX_NAME_LEN, ResStr + cursor, end - cursor);
    if (ResStr[end + 1] == '\n')
    {
        ++end;
    }
    cursor = ++end;
    // 下面是首部的解析，目前只能先考虑服务器是以\r\n结尾的
    // 现在已经创建了Headers数组，需要往里面添加首部
    while (true)
    {
        // 得到首部key
        while (ResStr[end] != ':' && ResStr[end] != '\r' && ResStr[end] != '\n')
        {
            end++;
        }
        if (cursor == end)
        {
            // 结束条件
            if (ResStr[end + 1] == '\n')
            {
                ++end;
            }
            cursor = ++end;
            break;
        }
        strncpy_s(KeyBuf, BUF_SIZE, ResStr + cursor, end - cursor);
        KeyBuf[end - cursor] = 0;
        ++end;
        cursor = ++end;
        // 得到首部value
        while (ResStr[end] != '\r' && ResStr[end] != '\n')
        {
            end++;
        }
        strncpy_s(buffer, BUF_SIZE, ResStr + cursor, end - cursor);
        buffer[end - cursor] = 0;
        // 创建首部键值对，添加到首部数组上
        cJSON* Header = cJSON_CreateObject();
        cJSON_AddStringToObject(Header, KeyBuf, buffer);
        cJSON_AddItemToArray(pResponse->ExtraHeaders, Header);
        NormalizeKeyStr(KeyBuf, buffer, BUF_SIZE);
        if (strcmp(buffer, "transfer-encoding") == 0)
        {
            NormalizeKeyStr(cJSON_GetObjectItem(Header, KeyBuf)->valuestring, buffer, BUF_SIZE);
            if (strcmp(buffer, "chunked") == 0)
            {
                pResponse->chunked = true;
            }
        }
        if (ResStr[end + 1] == '\n')
        {
            ++end;
        }
        cursor = ++end;
        pResponse->HeaderNum++;
    }
    // 除主体内容解析完毕
    *ParsedLen = cursor;
    return 0;
}

//void DisposeOfResponse(PRESPONSE pResponse)
//{
//	// 释放掉动态内存
//	if (pResponse->body)
//	{
//		free(pResponse->body);
//	}
//	if (pResponse->ContentType)
//	{
//		free(pResponse->ContentType);
//	}
//	if (pResponse->description)
//	{
//		free(pResponse->description);
//	}
//	if (pResponse->ExtraHeaders)
//	{
//		cJSON_Delete(pResponse->ExtraHeaders);
//	}
//}

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

void GetCookies(PSESSION session)
{
    char KeyBuf[BUF_SIZE];
    // 解析首部，填充特殊首部信息，生成Cookie数组
    cJSON* ArrayItem;
    for (int i = 0; i < session->response->HeaderNum; i++)
    {
        ArrayItem = cJSON_GetArrayItem(session->response->ExtraHeaders, i);
        NormalizeKeyStr(ArrayItem->child->string, KeyBuf, BUF_SIZE);
        if (strcmp(KeyBuf, "set-cookie") == 0 || strcmp(KeyBuf, "set-cookie2") == 0)
        {
            // 找到一个cookie
            cJSON* CookieArrayItem = ParseCookieString(ArrayItem->child->valuestring);
            int exist = CheckCookie(session->CookieJar, CookieArrayItem);
            if (exist == -1)
            {
                // 不存在这个cookie
                cJSON_AddItemToArray(session->CookieJar, CookieArrayItem);
                session->CookieNum++;
            }
            else
            {
                // 存在这个cookie，更新这个cookie
                cJSON_DeleteItemFromArray(session->CookieJar, exist);
                cJSON_AddItemToArray(session->CookieJar, CookieArrayItem);
            }
            cJSON_DeleteItemFromArray(session->response->ExtraHeaders, i--);
            session->response->HeaderNum--;
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

void AddHeader(PREQUEST request, const char* header)
{
    request->ExtraHeaders[request->HeaderNum] = (char*)malloc(strlen(header) + 1);
    strcpy_s(request->ExtraHeaders[request->HeaderNum++], strlen(header) + 1, header);	
}

