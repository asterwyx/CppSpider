#include "csr_error.h"

void rc::parse_retcode(uint64_t rc)
{
    if (rc == rc::SUCCESS)
    {
        CSR_INFO("Initialize all successfully.\n");
        return ;
    }
    for (int i = 0; i < rc::ERR_NUM; i++)
    {
        if (rc & (1Ui64) != 0)
        {
            CSR_ERROR("%s\n", rc::error_msgs[i]);
        }
        rc >>= 1;
    }
}