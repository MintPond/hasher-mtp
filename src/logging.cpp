// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "logging.h"
//#include "utiltime.h"
//#include "utilstrencodings.h"
#include <string>
#include <string.h>

using namespace std;


bool LogAcceptCategory(const char* category)
{
    return true;
}


int LogPrintStr(const std::string &str)
{
    int ret = 0; // Returns total number of characters written

        // print to console
    ret = fwrite(str.data(), 1, str.size(), stdout);
    fflush(stdout);

    return ret;
}
