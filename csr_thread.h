#pragma once
#include <Windows.h>

#ifdef WIN_NT
#define API     WINAPI
typedef DWORD   thrd_ret_t;
typedef FILE    file_t;
#else
#define API
typedef void *thrd_ret_t;
#endif
