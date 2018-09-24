

#ifndef BITCOIN_LOGGING_H
#define BITCOIN_LOGGING_H

#include "tinyformat.h"
#include "nan.h"

#include <atomic>
#include <exception>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>


#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)
#define THROW_ERROR_EXCEPTION_WITH_STATUS_CODE(x, y) NanThrowError(x, y)

/** Return true if log accepts specified category */
bool LogAcceptCategory(const char* category);

/** Send a string to the log output */
int LogPrintStr(const std::string &str);

#define LogPrintf(...) LogPrint(NULL, __VA_ARGS__)

template<typename T1, typename... Args>
static inline int LogPrint(const char* category, const char* fmt, const T1& v1, const Args&... args)
{
    if(!LogAcceptCategory(category)) return 0;
    return LogPrintStr(tfm::format(fmt, v1, args...));
}

template<typename T1, typename... Args>
bool error(const char* fmt, const T1& v1, const Args&... args)
{
    LogPrintStr("ERROR: " + tfm::format(fmt, v1, args...) + "\n");
    return false;
}

/**
 * Zero-arg versions of logging and error, these are not covered by
 * the variadic templates above (and don't take format arguments but
 * bare strings).
 */
static inline int LogPrint(const char* category, const char* s)
{
    if(!LogAcceptCategory(category)) return 0;
    return LogPrintStr(s);
}
static inline bool error(const char* s)
{
    LogPrintStr(std::string("ERROR: ") + s + "\n");
    return false;
}

#endif