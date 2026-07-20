// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file RegistrarDb.h
 * @brief Thread-safe SIP registrar binding store.
 */
#pragma once
#include "common.h"
#include "Transport.h"
#include <pthread.h>

namespace sip {

/** @brief One active or stale registration binding entry. */
struct RegBinding {
    /** Address-of-record, example sip:user at domain. */
    URI      aor;           // Address of Record
    /** Registered Contact URI for this endpoint. */
    URI      contact;       // Contact URI        sip:user@192.168.1.x:5060
    /** Source IP observed at registration time. */
    Str<48>  srcAddr;       // Source IP  (for NAT traversal, rport)
    /** Source port observed at registration time. */
    uint16_t srcPort   = 0;
    /** Transport protocol used for registration. */
    Proto    proto     = Proto::Udp;
    /** Absolute expiry time in milliseconds. */
    int64_t  expiresAt = 0;     // absolute ms (0 = expired/unused)
    /** Registration Call-ID used for replay/retransmit checks. */
    CallId   regCallId;          // to detect retransmissions
    /** Registration CSeq value. */
    uint32_t regCSeq   = 0;
    /** True when entry slot is in use. */
    bool     used      = false;
};

/** @brief AOR-to-contact registrar database with expiration management. */
class RegistrarDb {
public:
    /** Maximum number of binding entries stored. */
    static constexpr size_t MaxBindings = 2048;

    RegistrarDb();
    ~RegistrarDb();

    /**
     * @brief Register or refresh binding.
     * @return False when database has no free entry.
     */
    bool update(const char* aor, const char* contact,
                const char* srcAddr, uint16_t srcPort,
                Proto proto, uint32_t expiresSec,
                const char* callId, uint32_t cseq,
                int64_t nowMs);

    /** @brief Remove all bindings for an AOR. */
    void unregisterAll(const char* aor);

    /** @brief Copy active bindings for AOR into output buffer. */
    size_t findBindings(const char* aor,
                        RegBinding* out, size_t maxOut,
                        int64_t nowMs) const;

    /** @brief Check if AOR has at least one active binding. */
    bool hasBinding(const char* aor, int64_t nowMs) const;

    /** @brief Expire stale bindings; call from periodic tick. */
    void expire(int64_t nowMs);

    /** @brief Count active bindings. */
    size_t totalBindings() const;
    /** @brief Print active bindings for diagnostics. */
    void   printAll(int64_t nowMs) const;

private:
    RegBinding entries_[MaxBindings];
    mutable pthread_mutex_t mu_ = PTHREAD_MUTEX_INITIALIZER;
};

} // namespace sip
