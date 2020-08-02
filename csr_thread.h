#pragma once
#include <Windows.h>

#ifdef CSR_WINDOWS
#define API     WINAPI
typedef DWORD   thrd_ret_t;
typedef FILE    file_t;
typedef HANDLE  p_thrd_t;
#else
#define API
typedef void *thrd_ret_t;
#endif
