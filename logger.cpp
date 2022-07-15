#include "logger.hpp"
#include <cstdio>
#include <cstdarg>
#include <iostream>
namespace csr {
logger::logger(const std::string& name)
    : logger(name, DEFAULT_LEVEL) {}

logger::logger(const std::string& name, level lev)
    : logger(name, lev, "") {}

logger::logger(const std::string& name, level lev, const std::string& file)
    : m_name(name), m_level(lev), m_lock_guard()
{
    if (file == "") {
        m_file = stdout;
    } else {
        try
        {
            m_file = fopen(file.c_str(), "a+");
        }
        catch(const std::exception& e)
        {
            std::cerr << "Can't open log file to write, set to stdout." << std::endl;
            std::cerr << e.what() << std::endl;
            fclose(m_file);
            m_file = stdout;
        }
    }
}

int logger::log(level lev, const char *prompt, const char *msg, __gnuc_va_list fmt)
{
    if (lev >= m_level)
    {
        std::string str(prompt);
        str += std::string(" ") + msg;
        m_lock_guard.lock();
        int res = vfprintf(m_file, str.c_str(), fmt);
        m_lock_guard.unlock();
        return res;
    }
    else
    {
        return LOG_LEVEL_NOT_TURNED_ON;
    }
}

int logger::error(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    int res = log(level::ERROR, "ERROR:", msg, args);
    va_end(args);
    return res;
}

int logger::info(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    int res = log(level::INFO, "INFO:", msg, args);
    va_end(args);
    return res;
}

int logger::debug(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    int res = log(level::DEBUG, "DEBUG:", msg, args);
    va_end(args);
    return res;
}

int logger::warn(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    int res = log(level::WARN, "WARN:", msg, args);
    va_end(args);
    return res;
}

int logger::print(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    m_lock_guard.lock();
    int res = vprintf(msg, args);
    m_lock_guard.unlock();
    va_end(args);
    return res;
}
}