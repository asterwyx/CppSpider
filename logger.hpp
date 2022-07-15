#pragma once
#include <string>
#include "thread.hpp"
namespace csr
{

class logger {
public:
    static constexpr int LOG_LEVEL_NOT_TURNED_ON = -2;

    enum class level {
        DEBUG,
        INFO,
        WARN,
        ERROR
    };

    static const level DEFAULT_LEVEL = level::WARN;


public:
    logger(const std::string& name);
    logger(const std::string& name, level lev);
    logger(const std::string& name, level lev, const std::string& file);

public:
    int error(const char *msg, ...);
    int info(const char *msg, ...);
    int debug(const char *msg, ...);
    int warn(const char *msg, ...);
    int print(const char *msg, ...);

public:
    void set_level(level lev) noexcept
    {
        m_level = lev;
    }
    level get_level() noexcept
    {
        return m_level;
    }
    void set_name(std::string name) noexcept
    {
        m_name = name;
    }
    std::string get_name() noexcept
    {
        return m_name;
    }

private:
    int log(level lev, const char *prompt, const char *msg, __gnuc_va_list fmt);

private:
    std::string     m_name;
    level           m_level;
    mutex           m_lock_guard;
    FILE            *m_file;
};


} // namespace csr
