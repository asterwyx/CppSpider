#include <iostream>
#include <Windows.h>
#include <cstdlib>
#include "log.h"
using std::cerr;
using std::cout;
using std::endl;
using csr_log::print;

DWORD WINAPI TestThread(LPVOID lpParam)
{
    int tid = *(int *)lpParam;
    for (int i = 0; i < 10; i++)
    {
        // CSR_DEBUG("Hello, thread%d\n", tid);
        // print("Hello, thread%d\n", tid);
        printf("Hello, thread%d\n", tid);
        Sleep(rand() % 10);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int id[5];
    HANDLE hThreads[5];
    csr_log::init();
    for (int i = 0; i < 5; i++) {
        id[i] = i + 1;
        hThreads[i] = CreateThread(nullptr, 0, TestThread, id + i, 0, nullptr);
    }
    WaitForMultipleObjects(5, hThreads, TRUE, INFINITE);
}
