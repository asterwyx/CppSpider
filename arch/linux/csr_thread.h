#if !defined(CSR_THREAD_H)
#define CSR_THREAD_H
#include <pthread.h>
#include <memory>
using std::shared_ptr;
namespace csr {
class thread {
    public:
    thread();
    thread(const thread& other);
    ~thread();
    
    
    private:
    shared_ptr<pthread_mutex_t> lock_guard;

}; 

}

#endif