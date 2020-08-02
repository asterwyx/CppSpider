#pragma once
#include <cstdint>
#include "csr_log.h"

namespace rc {

constexpr uint16_t MAX_ERR_LEN = 100;
constexpr uint8_t ERR_NUM = 3;

const uint64_t SUCCESS = 0;
const uint64_t E_NOMEM = 1;
const uint64_t E_CONN_FAIL = 2;
const uint64_t E_WSA_FAIL = 4;

const char error_msgs[ERR_NUM][MAX_ERR_LEN] = {
    "Out of memory.",
    "Connect failed.",
    "WSA initialization failed."
};


void parse_retcode(uint64_t rc);

}
