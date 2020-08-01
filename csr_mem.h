#pragma once
#include <cstdint>
#include <Windows.h>
#include <vector>
#include <string>
#define MBUF_SIZE   (1024 * 1024)
#define MBUF_NUM    64

int csr_init_mem();

#define LOCK(l) do\
{\
    EnterCriticalSection(&(l));\
} while(0)

#define UNLOCK(l) do\
{\
    LeaveCriticalSection(&(l));\
} while(0)

namespace csr {

typedef CRITICAL_SECTION lock_t;


typedef struct mempool {
    std::string name;
    uint32_t n_ele_size;
    std::vector<void *> elements;
    std::vector<void *> unused;
    lock_t lock;
} mempool_t, *p_mempool_t;


typedef struct mbuf {
    uint32_t n_dsize;
    uint32_t n_dlength;
    p_mempool_t p_prt_mpool;
    byte data[0];
} mbuf_t, *p_mbuf_t;

p_mempool_t create_mempool(const char *name, uint32_t n_ele_size, uint32_t n_ele_num);
void mempool_put(p_mempool_t p_mpool, void *ele);
void *mempool_get(p_mempool_t p_mpool);
p_mbuf_t alloc_mbuf(p_mempool_t p_mpool);
void free_mbuf(p_mbuf_t p_mbuf);

}

