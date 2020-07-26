#include <iostream>
#include "SocketClient.h"
#include <iostream>
using std::cerr;
using std::cout;
using std::endl;
using std::string;

int main()
{
    InitScheduler();
    StartScheduler();
    cout << "Hello, World!" << endl;
    return 0;
}
