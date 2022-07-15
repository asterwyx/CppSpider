/**
 * @file thread.hpp
 * @author Astrea (yixue.wang@outlook.com)
 * @brief This file encapsulates pthread library. Provide users with a java-like thread class.
 * @version 0.1
 * @date 2022-07-10
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef CSR_THREAD_HPP
#define CSR_THREAD_HPP
#include <pthread.h>
#include <memory>
#include <iostream>
using std::shared_ptr;
namespace csr {
class thread {
public:
    static constexpr int UNBOUNBED_START    = -1;
    static constexpr int UNSTARTED_JOIN     = -2;
    static constexpr int UNSTARTED_DETACH   = -3;
    
    using id_t                  = pthread_t;
    using thread_routine_t      = void *(*)(void *);
    using native_attr_type      = pthread_attr_t;
    
    thread(thread_routine_t routine);
    thread(thread_routine_t routine, void *arg);
    thread();
    thread(const thread&) = delete;
    thread(thread&& other) {
        m_id = other.m_id;
        m_routine = other.m_routine;
        other.m_routine = nullptr;
        m_arg = other.m_arg;
        other.m_arg = nullptr;
        // m_lock_guard = other.m_lock_guard;
        // other.m_lock_guard = nullptr;
    }

    thread& operator=(const thread &) = delete;
    thread& operator=(thread && other)
    {
        m_id = other.m_id;
        m_routine = other.m_routine;
        other.m_routine = nullptr;
        m_arg = other.m_arg;
        other.m_arg = nullptr;
        // m_lock_guard = other.m_lock_guard;
        // other.m_lock_guard = nullptr;
        return *this;
    }

    // to start the routine
    int start();
    // join sub thread
    int join();
    // detach from sub thread
    int detach();

    // class id {
    // private:
    //     native_handle_type m_thread;
    // public:
    //     id() noexcept : m_thread() { }

    //     explicit
    //     id(native_handle_type id) : m_thread(id) { }

    // private:

    //     id operator=(const id &other) {
    //         if (this == &other)
    //             return *this;
    //         m_thread = other.m_thread;
    //         return *this;
    //     }
    //     friend class thread;
    //     friend bool
    //     operator==(id x, id y) noexcept;
    //     friend bool
    //     operator<(id x, id y) noexcept;
    //     template<class _CharT, class _Traits>
    //     friend std::basic_ostream<_CharT, _Traits>&
    //     operator<<(std::basic_ostream<_CharT, _Traits>& out, id _id);
    // };
    
    id_t get_id() const noexcept
    {
        return m_id;
    }

    void *fetch_thread_return() noexcept
    {
        void *tmp = m_thread_return;
        m_thread_return = nullptr;
        return tmp;
    }


    ~thread();
    
private:
    id_t                            m_id;
    thread_routine_t                m_routine;
    void                            *m_arg;
    void                            *m_thread_return;
    native_attr_type                *m_attr;
    // pthread_mutex_t                 *m_lock_guard;
    // pthread_mutexattr_t             *m_lock_attr;
};

class mutex {
public:
    using native_handle_type    = pthread_mutex_t;
    using native_attr_type      = pthread_mutexattr_t;
    mutex();
    mutex(const native_attr_type& attr);
    ~mutex();
    int lock();
    int unlock();
    int trylock();
private:
    native_handle_type  *m_lock_guard;
    native_attr_type    *m_attr;
};


}

#endif