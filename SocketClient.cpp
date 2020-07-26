#include "SocketClient.h"
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <iostream>
using std::cout;
using std::endl;
using std::cerr;
#pragma comment(lib, "ws2_32.lib")

static PTASK aTasks[MAX_TASK_NUM];
static WSAEVENT aEvents[MAX_TASK_NUM];
static int nTask = 0;
extern HANDLE g_hEventScheduler;

DWORD WINAPI scheduler(LPVOID lpParam)
{
    while (true)
    {
        /* the fourth arg is 0 means this function is nonblock */
        int index = WSAWaitForMultipleEvents(nTask, aEvents, FALSE, 0, FALSE);
        if (index == WSA_WAIT_FAILED)
        {
            int error = WSAGetLastError();
            switch (error)
            {
            case WSANOTINITIALISED:
                cerr << "Haven't init or init failed!" << endl;
                break;
            case WSAENETDOWN:
                cerr << "Network subsystem error!" << endl;
                break;
            default:
                break;
            }
        }
        else if (index == WSA_WAIT_TIMEOUT)
        {
            // no event to handle
            continue;
        }
        else
        {
            int nSktIdx = index - WSA_WAIT_EVENT_0;
            SOCKET socket = aTasks[nSktIdx]->socket;
            WSANETWORKEVENTS event;
            /* get actual network events and reset the WSAEvent */
            int ret = WSAEnumNetworkEvents(socket, aEvents[nSktIdx], &event);
            if (ret == SOCKET_ERROR)
            {
                // error
                continue;
            }
            if (event.lNetworkEvents & FD_ACCEPT)
            {
                continue;
            }
            else if (event.lNetworkEvents & FD_READ)
            {
                if (event.iErrorCode[FD_READ_BIT] == 0)
                {
                    aTasks[nSktIdx]->fRecvHandler(socket, nullptr);
                }
            }
            else if (event.lNetworkEvents & FD_CLOSE)
            {
                if (event.iErrorCode[FD_CLOSE_BIT] == 0)
                {
                    closesocket(socket);
                    cout << "Socket " << socket << " closed." << endl;
                    DestroyTask(&aTasks[nSktIdx]);
                    for (int i = nSktIdx; i < nTask; i++)
                    {
                        aTasks[i] = aTasks[i + 1];
                        aEvents[i] = aEvents[i + 1];
                    }
                    nTask--;
                }
            }
            else if (event.lNetworkEvents & FD_WRITE)
            {
                if (event.iErrorCode[FD_WRITE_BIT] == 0)
                {
                    char *pToSent = aTasks[nSktIdx]->aSendBuf;
                    int nReqLen = strlen(pToSent);
                    int nSentLen = 0;
                    while (nSentLen < nReqLen)
                    {
                        int len = send(socket, pToSent + nSentLen, nReqLen - nSentLen, 0);
                        if (len >= 0)
                        {
                            nSentLen += len;
                        }
                        else
                        {
                            break;
                        }
                    }
                    cout << "Sent " << nSentLen << " bytes." << endl;
                }
            }
            
        }
        
    }
}

int AddTask(PTASK pTask)
{
    /* check full */
    if (nTask >= MAX_TASK_NUM)
    {
        cerr << "Task queue is full." << endl;
        return rc::E_NOMEM;
    }
    aTasks[nTask] = pTask;
    pTask->bStarted = true;
    if (aEvents[nTask] == nullptr) {
        aEvents[nTask] = WSACreateEvent();
    }
    int rc = WSAConnect(pTask->socket, pTask->pAddrInfo->ai_addr, sizeof(*pTask->pAddrInfo->ai_addr), nullptr, nullptr, nullptr, nullptr);
    if (rc == 0) {
        cout << "Connect server successfully." << endl;
    } else {
        cerr << "Cannot connect to server." << endl;
        return rc::E_CONN_FAIL;
    }
    WSAEventSelect(pTask->socket, aEvents[nTask], FD_READ | FD_WRITE | FD_CLOSE);
    pTask->bStarted = true;
    nTask++;
    return rc::SUCCESS;
}


void InitScheduler()
{
    /* initialize WinSock2 */
    WSAData WsaData;
    WORD SockVersion = MAKEWORD(2, 2);
    if (WSAStartup(SockVersion, &WsaData) != 0)
    {
        cerr << "Cannot start WinSock2!" << endl;
        exit(EXIT_FAILURE);
    }
    /* initialize events array */
    memset(aEvents, 0, sizeof(WSAEVENT) * MAX_TASK_NUM);
}

void StartScheduler()
{
    /* start scheduler thread */
    g_hEventScheduler = CreateThread(nullptr, 0, scheduler, nullptr, 0, nullptr);
}

PTASK CreateTask(PVOID pArgs, size_t nBufSize)
{
    auto result = (PTASK)malloc(sizeof(TASK) + nBufSize);
    result->socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    result->pArgs = pArgs;
    result->pAddrInfo = nullptr;
    result->bArgsAttached = false;
    result->bStarted = false;
    result->bFinished = false;
    result->fRecvHandler = nullptr;
    return result;
}

void DestroyTask(PTASK* pPTask)
{
    if (pPTask == NULL || (*pPTask) == NULL)
    {
        return;
    }
    if ((*pPTask)->bArgsAttached)
    {
        free((*pPTask)->pArgs);
    }
    free(*pPTask);
    *pPTask = NULL;
}
