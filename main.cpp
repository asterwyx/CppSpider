#include "logger.hpp"
#include "thread.hpp"
#include <unistd.h>
#include <cstdlib>
using std::cerr;
using std::cout;
using std::endl;


class factory {
public:
    
    static csr::logger* get_instance()
    {
        if (!sys_logger)
            sys_logger = new csr::logger("factory logger", csr::logger::level::ERROR);
        return sys_logger;
    }

    static void *worker(void *lpParam)
    {
        auto glogger = get_instance();
        int tid = *(int *)lpParam;
        sleep(rand() % 10 + 1);
        glogger->debug("Hello, thread %d.\n", tid);
        glogger->error("Hello, thread %d.\n", tid);
        return lpParam;
    }

private:

    class deletor
    {
    public:
        deletor();
        ~deletor()
        {
            if (factory::sys_logger != nullptr)
                delete sys_logger;
        }
    };
    static csr::logger    *sys_logger;
    static deletor        delr;
};

csr::logger *factory::sys_logger = nullptr;

int main(int argc, char *argv[])
{
    srand(0);
    int tid[10];
    for (int i = 0; i < 10; i++) {
        tid[i] = i;
        csr::thread slave(factory::worker, &tid[i]);
        slave.start();
        slave.join();
    }
    getchar();
    return 0;
}
