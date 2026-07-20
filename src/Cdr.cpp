// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// Cdr.cpp
#include "Cdr.h"
#include <cstdio>
#include <cstring>
#include <ctime>

namespace sip {

bool CdrLogger::open(const char* path) {
    if (path && *path) {
        fp_ = fopen(path, "a");
        if (!fp_) { perror(path); return false; }
        // Write CSV header if file is empty
        fseek(fp_,0,SEEK_END);
        if (ftell(fp_)==0)
            fprintf(fp_,"timestamp,call_id,from_uri,to_uri,direction,"
                        "start_ms,connect_ms,end_ms,duration_ms,"
                        "result_code,result_text\n");
        fflush(fp_);
    }
    return true;
}

void CdrLogger::close() {
    pthread_mutex_lock(&mu_);
    if (fp_) { fflush(fp_); fclose(fp_); fp_=nullptr; }
    pthread_mutex_unlock(&mu_);
}

void CdrLogger::isoTime(int64_t ms, char* buf, size_t len) {
    time_t t = (time_t)(ms/1000);
    struct tm* tm = gmtime(&t);
    snprintf(buf,len,"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday,
             tm->tm_hour,tm->tm_min,tm->tm_sec,(int)(ms%1000));
}

static const char* resultStr(CdrResult r) {
    switch(r) {
    case CdrResult::Answered:  return "ANSWERED";
    case CdrResult::NoAnswer:  return "NO_ANSWER";
    case CdrResult::Busy:      return "BUSY";
    case CdrResult::Rejected:  return "REJECTED";
    case CdrResult::Cancelled: return "CANCELLED";
    default:                   return "ERROR";
    }
}

void CdrLogger::write(const CdrRecord& rec) {
    char ts[32];
    isoTime(rec.startMs, ts, sizeof ts);
    int64_t dur = (rec.connectMs>0 && rec.endMs>0)
                ? (rec.endMs - rec.connectMs) : 0;

    pthread_mutex_lock(&mu_);
    FILE* f = fp_ ? fp_ : stdout;
    fprintf(f,"%s,%s,%s,%s,%s,%lld,%lld,%lld,%lld,%d,%s\n",
            ts,
            rec.callId.c_str(),
            rec.fromUri.c_str(),
            rec.toUri.c_str(),
            rec.outbound ? "OUT" : "IN",
            (long long)rec.startMs,
            (long long)rec.connectMs,
            (long long)rec.endMs,
            (long long)dur,
            rec.sipCode,
            resultStr(rec.result));
    if (fp_) fflush(fp_);
    pthread_mutex_unlock(&mu_);
}

} // namespace sip
