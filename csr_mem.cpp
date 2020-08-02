#include "csr_mem.h"
#include <cstdlib>
#include <list>
#include <Windows.h>

#include "csr_log.h"
#include "csr_error.h"

using csr::mempool_t;
using csr::mbuf_t;
using csr::p_mbuf_t;
using csr::p_mempool_t;

p_mempool_t g_csr_mp;

static std::list<p_mempool_t> g_mempools;

uint64_t csr_init_mem()
{
    g_csr_mp = csr::create_mempool("cpp_spider", sizeof(mbuf_t) + MBUF_SIZE, MBUF_NUM);
    g_mempools.push_back(g_csr_mp);
    return rc::SUCCESS;
}

p_mempool_t csr::create_mempool(const char *name, uint32_t n_ele_size, uint32_t n_ele_num)
{
    auto p_mpl = new mempool_t;
    p_mpl->name = name;
    InitializeCriticalSection(&p_mpl->lock);
    p_mpl->n_ele_size = n_ele_size;
    for (int i = 0; i < n_ele_num; i++)
    {
        auto ele = malloc(n_ele_size);
        p_mpl->elements.push_back(ele);
        p_mpl->unused.push_back(ele);
    }
    return p_mpl;
}

void *csr::mempool_get(p_mempool_t p_mpool)
{
    LOCK(p_mpool->lock);
    auto result = p_mpool->unused.back();
    p_mpool->unused.pop_back();
    UNLOCK(p_mpool->lock);
    return result;
}

void csr::mempool_put(p_mempool_t p_mpool, void *ele)
{
    LOCK(p_mpool->lock);
    p_mpool->unused.push_back(ele);
    UNLOCK(p_mpool->lock);
}

p_mbuf_t csr::alloc_mbuf(p_mempool_t p_mpool)
{
    auto result = (p_mbuf_t)mempool_get(p_mpool);
    result->n_dlength = 0;
    result->n_dsize = p_mpool->n_ele_size - sizeof(mbuf_t);
    result->p_prt_mpool = p_mpool;
    return result;
}

void csr::free_mbuf(p_mbuf_t p_mbuf)
{
    mempool_put(p_mbuf->p_prt_mpool, p_mbuf);
}
