#include <Windows.h>
#include <cstdio>
#include <cstdarg>
#include <iostream>

#include "csr_log.h"

namespace csr_log {

LEVEL g_eAppLev = LEVEL::L_DEBUG;

static CRITICAL_SECTION g_sCS;

int init()
{
    InitializeCriticalSection(&g_sCS);
    return 0;
}

void log(LEVEL lev, const char *prompt, const char *msg, ...)
{
    if (lev >= g_eAppLev)
    {
        std::string str;
        str = str + prompt + " " + msg;
        va_list args;
        va_start(args, msg);
        EnterCriticalSection(&g_sCS);
        vprintf(str.c_str(), args);
        LeaveCriticalSection(&g_sCS);
        va_end(args);
    }
}


void print(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    EnterCriticalSection(&g_sCS);
    vprintf(msg, args);
    LeaveCriticalSection(&g_sCS);
    va_end(args);
}

}
