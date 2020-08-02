#pragma once
#include <cstdint>

#define CSR_DEBUG(msg, ...) do\
{\
    csr::log(csr::level_t::L_DEBUG, "CSR DEBUG:", (msg), ##__VA_ARGS__);\
} while(0)

#define CSR_INFO(msg, ...) do\
{\
    csr::log(csr::level_t::L_INFO, "CSR INFO:", (msg), ##__VA_ARGS__);\
} while(0)

#define CSR_WARN(msg, ...) do\
{\
    csr::log(csr::level_t::L_WARN, "CSR WARN:", (msg), ##__VA_ARGS__);\
} while(0)

#define CSR_ERROR(msg, ...) do\
{\
    csr::log(csr::level_t::L_ERROR, "CSR ERROR:", (msg), ##__VA_ARGS__);\
} while(0)

uint64_t csr_init_log();
namespace csr{

typedef enum level {
    L_DEBUG,
    L_INFO,
    L_WARN,
    L_ERROR
} level_t;

extern level_t ge_app_lev;

void log(level_t lev, const char *prompt, const char *msg, ...);

void print(const char *msg, ...);

}

