#include "csr_socket.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <iostream>

#include "csr_log.h"

using std::cout;
using std::endl;
using std::cerr;
using csr::p_task_t;
using csr::task_t;
#pragma comment(lib, "ws2_32.lib")

static p_task_t a_tasks[MAX_TASK_NUM];
static WSAEVENT a_events[MAX_TASK_NUM];
static int n_task = 0;
HANDLE gh_event_scheduler;

DWORD WINAPI scheduler(LPVOID lpParam)
{
    while (true)
    {
        /* the fourth arg is 0 means this function is nonblock */
        int index = WSAWaitForMultipleEvents(n_task, a_events, FALSE, 0, FALSE);
        if (index == WSA_WAIT_FAILED)
        {
            int error = WSAGetLastError();
            switch (error)
            {
            case WSANOTINITIALISED:
                CSR_ERROR("Haven't init or init failed!\n");
                break;
            case WSAENETDOWN:
                CSR_ERROR("Network subsystem error!\n");
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
            SOCKET socket = a_tasks[nSktIdx]->socket;
            WSANETWORKEVENTS event;
            /* get actual network events and reset the WSAEvent */
            int ret = WSAEnumNetworkEvents(socket, a_events[nSktIdx], &event);
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
                    CSR_DEBUG("Socket %llu receive some bytes.\n", socket);
                    a_tasks[nSktIdx]->f_recv_handler(socket, a_tasks[nSktIdx]->p_args);
                }
            }
            else if (event.lNetworkEvents & FD_CLOSE)
            {
                if (event.iErrorCode[FD_CLOSE_BIT] == 0)
                {
                    closesocket(socket);
                    CSR_DEBUG("Socket %llu closed.\n", socket);
                    csr::destroy_task(&a_tasks[nSktIdx]);
                    for (int i = nSktIdx; i < n_task; i++)
                    {
                        a_tasks[i] = a_tasks[i + 1];
                        a_events[i] = a_events[i + 1];
                    }
                    n_task--;
                }
            }
            else if (event.lNetworkEvents & FD_WRITE)
            {
                if (event.iErrorCode[FD_WRITE_BIT] == 0)
                {
                    char *pToSent = a_tasks[nSktIdx]->p_send_buf;
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
                    CSR_DEBUG("Socket %llu send %d bytes.\n", socket, nSentLen);
                }
            }
            
        }
        
    }
}

uint64_t csr_init_socket()
{
/* initialize WinSock2 */
    WSAData wsa_data;
    WORD skt_ver = MAKEWORD(2, 2);
    if (WSAStartup(skt_ver, &wsa_data) != 0)
    {
        CSR_ERROR("Cannot start WinSock2!\n");
        return rc::E_WSA_FAIL;
    }
    /* initialize events array */
    memset(a_events, 0, sizeof(WSAEVENT) * MAX_TASK_NUM);
    return rc::SUCCESS;
}

int csr::add_task(p_task_t p_task)
{
    /* check full */
    if (n_task >= MAX_TASK_NUM)
    {
        CSR_ERROR("Task queue is full!\n");
        return rc::E_NOMEM;
    }
    a_tasks[n_task] = p_task;
    p_task->b_started = true;
    if (a_events[n_task] == nullptr) {
        a_events[n_task] = WSACreateEvent();
    }
    int rc = connect(p_task->socket, p_task->p_addrinfo->ai_addr, sizeof(*p_task->p_addrinfo->ai_addr));
    if (rc == 0) {
        CSR_DEBUG("Socket %llu connect successfully.\n", p_task->socket);
    } else {
        CSR_ERROR("Socket %llu connection failed!\n", p_task->socket);
        return rc::E_CONN_FAIL;
    }
    WSAEventSelect(p_task->socket, a_events[n_task], FD_READ | FD_WRITE | FD_CLOSE);
    p_task->b_started = true;
    n_task++;
    return rc::SUCCESS;
}

void csr::start_scheduler()
{
    /* start scheduler thread */
    ::gh_event_scheduler = CreateThread(nullptr, 0, scheduler, nullptr, 0, nullptr);
}

p_task_t csr::create_task(void *p_args, size_t n_buf_size)
{
    auto result = (p_task_t)malloc(sizeof(task_t) + n_buf_size);
    result->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    result->p_args = p_args;
    result->p_addrinfo = nullptr;
    result->b_args_attached = false;
    result->b_started = false;
    result->b_finished = false;
    result->f_recv_handler = nullptr;
    return result;
}

void csr::destroy_task(p_task_t* pPTask)
{
    if (pPTask == NULL || (*pPTask) == NULL)
    {
        return;
    }
    if ((*pPTask)->b_args_attached)
    {
        free((*pPTask)->p_args);
    }
    free(*pPTask);
    *pPTask = NULL;
}
