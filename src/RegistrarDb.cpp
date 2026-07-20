// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// RegistrarDb.cpp
#include "RegistrarDb.h"
#include <cstdio>
#include <cstring>
#include <ctime>

namespace sip {

RegistrarDb::RegistrarDb() { memset(entries_,0,sizeof entries_); }
RegistrarDb::~RegistrarDb() { pthread_mutex_destroy(&mu_); }

bool RegistrarDb::update(const char* aor, const char* contact,
                         const char* srcAddr, uint16_t srcPort,
                         Proto proto, uint32_t expiresSec,
                         const char* callId, uint32_t cseq, int64_t nowMs) {
    pthread_mutex_lock(&mu_);

    // Find existing binding for this AOR+contact pair
    for (auto& b : entries_) {
        if (!b.used) continue;
        if (!(b.aor==aor)) continue;
        if (!(b.contact==contact)) continue;
        // Retransmission check: same Call-ID, lower CSeq → ignore
        if (b.regCallId==callId && cseq < b.regCSeq) {
            pthread_mutex_unlock(&mu_); return true;
        }
        if (expiresSec == 0) {
            b.used = false;    // explicit unregister
        } else {
            b.expiresAt = nowMs + (int64_t)expiresSec * 1000;
            b.srcAddr.assign(srcAddr, strlen(srcAddr));
            b.srcPort  = srcPort;
            b.proto    = proto;
            b.regCallId.assign(callId, strlen(callId));
            b.regCSeq  = cseq;
        }
        pthread_mutex_unlock(&mu_); return true;
    }

    if (expiresSec == 0) { pthread_mutex_unlock(&mu_); return true; } // unregister non-existent

    // New binding
    for (auto& b : entries_) {
        if (!b.used) {
            b.used    = true;
            b.aor.assign(aor,     strlen(aor));
            b.contact.assign(contact, strlen(contact));
            b.srcAddr.assign(srcAddr, strlen(srcAddr));
            b.srcPort  = srcPort;
            b.proto    = proto;
            b.expiresAt= nowMs + (int64_t)expiresSec * 1000;
            b.regCallId.assign(callId, strlen(callId));
            b.regCSeq  = cseq;
            pthread_mutex_unlock(&mu_); return true;
        }
    }
    pthread_mutex_unlock(&mu_); return false; // full
}

void RegistrarDb::unregisterAll(const char* aor) {
    pthread_mutex_lock(&mu_);
    for (auto& b : entries_) if (b.used && b.aor==aor) b.used=false;
    pthread_mutex_unlock(&mu_);
}

size_t RegistrarDb::findBindings(const char* aor,
                                 RegBinding* out, size_t maxOut,
                                 int64_t nowMs) const {
    size_t n = 0;
    pthread_mutex_lock(&mu_);
    for (const auto& b : entries_) {
        if (!b.used) continue;
        if (!(b.aor==aor)) continue;
        if (b.expiresAt <= nowMs) continue;
        if (n < maxOut) out[n++] = b;
    }
    pthread_mutex_unlock(&mu_);
    return n;
}

bool RegistrarDb::hasBinding(const char* aor, int64_t nowMs) const {
    RegBinding b;
    return findBindings(aor, &b, 1, nowMs) > 0;
}

void RegistrarDb::expire(int64_t nowMs) {
    pthread_mutex_lock(&mu_);
    for (auto& b : entries_) if (b.used && b.expiresAt<=nowMs) b.used=false;
    pthread_mutex_unlock(&mu_);
}

size_t RegistrarDb::totalBindings() const {
    size_t n=0; pthread_mutex_lock(&mu_);
    for (const auto& b : entries_) if (b.used) ++n;
    pthread_mutex_unlock(&mu_); return n;
}

void RegistrarDb::printAll(int64_t nowMs) const {
    printf("%-30s %-40s %-8s %s\n","AOR","Contact","Proto","Expires");
    printf("%-30s %-40s %-8s %s\n","---","-------","-----","-------");
    pthread_mutex_lock(&mu_);
    for (const auto& b : entries_) {
        if (!b.used) continue;
        int64_t left = (b.expiresAt - nowMs) / 1000;
        printf("%-30s %-40s %-8s %llds\n",
               b.aor.c_str(), b.contact.c_str(),
               b.proto==Proto::Tcp?"TCP":"UDP",
               (long long)left);
    }
    pthread_mutex_unlock(&mu_);
}

} // namespace sip
