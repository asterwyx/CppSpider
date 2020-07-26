#pragma once
#include "HttpLib.h"
#include <stdio.h>

int main()
{
    if (InitWSA() != 0)
    {
        fprintf(stderr, "WSAStartup failed!\n");
    }
    // 测试一下得到的主机ip是否正确
    PSESSION session = CreateSession("qiming.hust.edu.cn");
    char headers[][MAX_HEADER_LEN] = {
        "Accept: *",
        "Host: qiming.hust.edu.cn",
        "Connection: keep-alive",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
    };
    for (int i = 0; i < 4; i++)
    {
        AddHeader(session->request, headers[i]);
    }
    sprintf_s(session->response->BodyFileName, MAX_NAME_LEN, "qiming.html");
    int status = HttpRequest(session);
    DestroySession(&session);
    Dispose();
    return 0;
}