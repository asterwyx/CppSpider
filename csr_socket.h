#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include "csr_def.h"

#define MAX_TASK_NUM                64

typedef void (*RecvCallback)(SOCKET, PVOID);



typedef struct Task {
    SOCKET socket;
    PADDRINFOA pAddrInfo;
    PVOID pArgs;
    bool bArgsAttached;
    RecvCallback fRecvHandler;
    bool bStarted;
    bool bFinished;
    char aSendBuf[0];
} TASK, *PTASK;

extern HANDLE g_hEventScheduler;

int AddTask(PTASK pTask);
void InitScheduler();
void StartScheduler();
PTASK CreateTask(PVOID pArgs, size_t nBufSize);
void DestroyTask(PTASK* pPTask);
