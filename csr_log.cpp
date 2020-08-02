#include <Windows.h>
#include <cstdio>
#include <cstdarg>
#include <iostream>

#include "csr_log.h"
#include "csr_error.h"


csr::level_t csr::ge_app_lev = csr::level_t::L_DEBUG;

static CRITICAL_SECTION gs_cs;

uint64_t csr_init_log()
{
    InitializeCriticalSection(&gs_cs);
    return rc::SUCCESS;
}

void csr::log(level_t lev, const char *prompt, const char *msg, ...)
{
    if (lev >= ge_app_lev)
    {
        std::string str;
        str = str + prompt + " " + msg;
        va_list args;
        va_start(args, msg);
        EnterCriticalSection(&gs_cs);
        vprintf(str.c_str(), args);
        LeaveCriticalSection(&gs_cs);
        va_end(args);
    }
}


void csr::print(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    EnterCriticalSection(&gs_cs);
    vprintf(msg, args);
    LeaveCriticalSection(&gs_cs);
    va_end(args);
}
