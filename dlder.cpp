#pragma once
#include <stdio.h>

#include "csr_main.h"

extern HANDLE gh_event_scheduler;

int main()
{
    uint64_t ret = csr_init();
    rc::parse_retcode(ret);
    if (ret != rc::SUCCESS)
    {
        return -1;
    }
    p_session_t session = create_session("qiming.hust.edu.cn");
    char headers[][MAX_HEADER_LEN] = {
        "Accept: *",
        "Host: qiming.hust.edu.cn",
        "Connection: close",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
    };
    for (int i = 0; i < 4; i++)
    {
        add_header(session->request, headers[i]);
    }
    sprintf_s(session->response->body_filename, MAX_NAME_LEN, "qiming.html");
    int status = http_request(session);
    WaitForSingleObject(gh_event_scheduler, INFINITE);
    destroy_session(&session);
    dispose();
    return 0;
}