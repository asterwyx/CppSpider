#pragma once
#ifndef _SOCKET_CLIENT_H_
#define _SOCKET_CLIENT_H_

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#define MAX_TASK_NUM                64
#define CreateTaskT(type, size)     (PTASK result = CreateTask(malloc(sizeof(type)), (size)), result->bArgsAttached = true, result)

typedef void (*RecvCallback)(SOCKET socket, PVOID pParam);

namespace rc {
    const int SUCCESS = 0;
    const int E_NOMEM = -1;
    const int E_CONN_FAIL = -2;
}

typedef struct Task {
    SOCKET socket;
    ADDRINFO sAddrInfo;
    PVOID pArgs;
    bool bArgsAttached;
    RecvCallback fRecvHandler;
    bool bStarted;
    bool bFinished;
    char aSendBuf[0];
} TASK, *PTASK;

int AddTask(PTASK pTask);
void InitScheduler();
void StartScheduler();
PTASK CreateTask(PVOID pArgs, size_t nBufSize);
void DestroyTask(PTASK* pPTask);


#endif // !_SOCKET_CLIENT_H_
