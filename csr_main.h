#pragma once

#include <cstdint>

#include "csr_error.h"
#include "csr_http.h"
#include "csr_log.h"
#include "csr_mem.h"
#include "csr_regex.h"
#include "csr_socket.h"
#include "csr_thread.h"

uint64_t csr_init()
{
    uint64_t result = rc::SUCCESS;
    result |= csr_init_log();
    result |= csr_init_mem();
    result |= csr_init_socket();
    result |= csr_init_http();
    return result;
}