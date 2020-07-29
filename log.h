#pragma once

#define CSR_DEBUG(msg, ...) do\
{\
    csr_log::log(csr_log::LEVEL::L_DEBUG, "CSR DEBUG:", (msg), ##__VA_ARGS__);\
} while(0)

#define CSR_INFO(msg, ...) do\
{\
    csr_log::log(csr_log::LEVEL::L_INFO, "CSR INFO:", (msg), ##__VA_ARGS__);\
} while(0)

#define CSR_WARN(msg, ...) do\
{\
    csr_log::log(csr_log::LEVEL::L_WARN, "CSR WARN:", (msg), ##__VA_ARGS__);\
} while(0)

#define CSR_ERROR(msg, ...) do\
{\
    csr_log::log(csr_log::LEVEL::L_ERROR, "CSR ERROR:", (msg), ##__VA_ARGS__);\
} while(0)

namespace csr_log{

typedef enum Level {
    L_DEBUG,
    L_INFO,
    L_WARN,
    L_ERROR
} LEVEL;

extern LEVEL g_eAppLev;

int init();

void log(LEVEL lev, const char *prompt, const char *msg, ...);

void print(const char *msg, ...);

}

