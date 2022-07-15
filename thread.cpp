#include "thread.hpp"
#include <iostream>
using std::cerr;
using std::endl;

namespace csr {

thread::thread(thread_routine_t routine, void *arg) 
    : m_id(0), m_routine(routine), m_arg(arg), m_thread_return(nullptr)
{
    this->m_attr = new pthread_attr_t;
    // this->m_lock_guard = new pthread_mutex_t;
    // this->m_lock_attr = new pthread_mutexattr_t;
    // initialize thread attribute.
    pthread_attr_init(this->m_attr);
    // pthread_mutexattr_init(this->m_lock_attr);
    // pthread_mutex_init(this->m_lock_guard, this->m_lock_attr);
}

thread::thread(thread_routine_t routine) : thread(routine, nullptr) { }

thread::thread() : thread(nullptr, nullptr) { }

thread::~thread()
{
    // pthread_mutex_destroy(this->m_lock_guard);
    // delete this->m_lock_guard;
    // pthread_m utexattr_destroy(this->m_lock_attr);
    // delete this->m_lock_attr;
    pthread_attr_destroy(this->m_attr);
    delete this->m_attr;
    if (this->m_thread_return)
        cerr << "Please fetch thread return and deal with it." << endl;
        
}


int thread::start()
{
    if (this->m_routine)
    {
        return pthread_create(&this->m_id, this->m_attr, this->m_routine, this->m_arg);
    }
    else
    {
        return UNBOUNBED_START;
    }
}

int thread::join()
{
    if (!this->m_id)
    {
        return UNSTARTED_JOIN;
    }
    else
    {
        return pthread_join(this->m_id, &this->m_thread_return);
    }
}

int thread::detach()
{
    if (!this->m_id)
    {
        return UNSTARTED_DETACH;
    }
    else
    {
        return pthread_detach(this->m_id);
    }
}

mutex::mutex()
{
    m_lock_guard = new native_handle_type;
    m_attr = new native_attr_type;
    pthread_mutexattr_init(this->m_attr);
    pthread_mutex_init(this->m_lock_guard, this->m_attr);
}

mutex::mutex(const native_attr_type& attr)
{
    m_lock_guard = new native_handle_type;
    m_attr = new native_attr_type;
    *m_attr = attr;
    pthread_mutex_init(this->m_lock_guard, this->m_attr);
}

mutex::~mutex()
{
    pthread_mutex_destroy(this->m_lock_guard);
    delete this->m_lock_guard;
    pthread_mutexattr_destroy(this->m_attr);
    delete this->m_attr;
}

int mutex::lock()
{
    return pthread_mutex_lock(this->m_lock_guard);
}

int mutex::unlock()
{
    return pthread_mutex_unlock(this->m_lock_guard);
}

int mutex::trylock()
{
    return pthread_mutex_trylock(this->m_lock_guard);
}

}