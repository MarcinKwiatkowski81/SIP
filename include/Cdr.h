// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file Cdr.h
 * @brief Call Detail Record model and CSV logger.
 */
#pragma once
#include "common.h"
#include <cstdio>
#include <pthread.h>

namespace sip {

/** @brief End-of-call result category used in CDR output. */
enum class CdrResult : uint8_t {
    Answered   = 0,
    NoAnswer,
    Busy,
    Rejected,
    Error,
    Cancelled,
};

/** @brief One call detail record entry. */
struct CdrRecord {
    /** SIP Call-ID. */
    CallId   callId;
    /** Originating party URI. */
    URI      fromUri;
    /** Destination party URI. */
    URI      toUri;
    /** True when call was initiated locally. */
    bool     outbound = true;    // true = we initiated
    /** Call start time in ms since epoch. */
    int64_t  startMs  = 0;       // INVITE sent/received
    /** Call connect time in ms since epoch. */
    int64_t  connectMs = 0;      // 200 OK
    /** Call end time in ms since epoch. */
    int64_t  endMs    = 0;       // BYE / final response
    /** High-level result classification. */
    CdrResult result  = CdrResult::NoAnswer;
    /** Final SIP status code associated with call completion. */
    int       sipCode = 0;
};

/** @brief Thread-safe CSV CDR writer. */
class CdrLogger {
public:
    /** @brief Open output stream. path=nullptr logs to stdout. */
    bool open(const char* path);
    /** @brief Close output stream if open. */
    void close();

    /** @brief Write one CDR row. */
    void write(const CdrRecord& rec);

private:
    FILE*           fp_  = nullptr;
    pthread_mutex_t mu_  = PTHREAD_MUTEX_INITIALIZER;
    static void isoTime(int64_t ms, char* buf, size_t len);
};

} // namespace sip
