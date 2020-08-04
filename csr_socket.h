#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <cstdint>

#include "csr_error.h"

#define MAX_TASK_NUM                64

uint64_t csr_init_socket();
namespace csr{
typedef void (*recv_callback_t)(SOCKET, void *);

extern HANDLE gh_event_scheduler;

typedef struct task {
    SOCKET socket;
    PADDRINFOA p_addrinfo;
    void *p_args;
    bool b_args_attached;
    recv_callback_t f_recv_handler;
    bool b_started;
    bool b_finished;
    char p_send_buf[0];
} task_t, *p_task_t;

int add_task(p_task_t p_task);
void start_scheduler();
void signal_finish();
bool is_queue_empty();
p_task_t create_task(void *p_args, size_t n_buf_size);
void destroy_task(p_task_t* pPTask);
}