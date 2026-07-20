// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// Uri.cpp – SIP URI parser/formatter (RFC 3261 §19)
#include "Uri.h"
#include <cstring>
#include <cctype>
#include <cstdio>

namespace sip {

static bool startsWith(const char* s, size_t sl, const char* pfx) {
    size_t pl = strlen(pfx);
    return sl >= pl && strncasecmp(s, pfx, pl) == 0;
}

Result<SipUri> SipUri::parse(const char* s, size_t len) {
    SipUri u;
    const char* end = s + len;
    const char* p   = s;

    // Scheme
    if (startsWith(p, (size_t)(end-p), "sips:")) {
        u.scheme = Scheme::Sips; p += 5;
    } else if (startsWith(p, (size_t)(end-p), "sip:")) {
        u.scheme = Scheme::Sip;  p += 4;
    } else if (startsWith(p, (size_t)(end-p), "tel:")) {
        u.scheme = Scheme::Tel;  p += 4;
    } else {
        // Assume bare user@host (no scheme)
        u.scheme = Scheme::Sip;
    }

    // Find '@' to split userinfo from hostport
    const char* at = nullptr;
    for (const char* q = p; q < end && *q != ';' && *q != '?' && *q != '>'; ++q)
        if (*q == '@') { at = q; break; }

    const char* hostStart;
    if (at) {
        u.user.assign(p, (size_t)(at - p));
        hostStart = at + 1;
    } else {
        hostStart = p;
    }

    // Find end of host:port (stop at ; ? >)
    const char* hostEnd = hostStart;
    while (hostEnd < end && *hostEnd != ';' && *hostEnd != '?' && *hostEnd != '>') ++hostEnd;

    // Split host:port
    const char* colon = nullptr;
    // Check for IPv6 literal
    if (hostStart < hostEnd && *hostStart == '[') {
        const char* rb = (const char*)memchr(hostStart, ']', (size_t)(hostEnd-hostStart));
        if (rb && rb+1 < hostEnd && *(rb+1) == ':') colon = rb+1;
    } else {
        for (const char* q = hostStart; q < hostEnd; ++q)
            if (*q == ':') { colon = q; break; }
    }

    if (colon) {
        u.host.assign(hostStart, (size_t)(colon - hostStart));
        u.port = (uint16_t)strtoul(colon+1, nullptr, 10);
    } else {
        u.host.assign(hostStart, (size_t)(hostEnd - hostStart));
    }

    // Parameters (everything after ';' up to '?' or '>')
    if (hostEnd < end && *hostEnd == ';') {
        const char* pEnd = hostEnd;
        while (pEnd < end && *pEnd != '?' && *pEnd != '>') ++pEnd;
        u.params.assign(hostEnd, (size_t)(pEnd - hostEnd));
    }

    if (u.host.empty()) return Err::Parse;
    return u;
}

int SipUri::format(char* buf, size_t sz) const {
    const char* sch = (scheme == Scheme::Sips) ? "sips:" :
                      (scheme == Scheme::Tel)  ? "tel:"  : "sip:";
    int n = 0;
    auto W = [&](const char* s, size_t l) {
        if ((size_t)n + l < sz) { memcpy(buf+n, s, l); n += (int)l; }
        else n = (int)sz + 1; // signal overflow
    };
    W(sch, strlen(sch));
    if (!user.empty()) { W(user.c_str(), user.len); W("@", 1); }
    W(host.c_str(), host.len);
    if (port) {
        char pb[8]; int pl = snprintf(pb, sizeof pb, ":%u", port);
        W(pb, (size_t)pl);
    }
    if (!params.empty()) W(params.c_str(), params.len);
    if ((size_t)n >= sz) return 0;
    buf[n] = 0;
    return n;
}

void SipUri::transport(char* out, size_t outsz) const {
    // Default
    strncpy(out, "udp", outsz);
    // Scan params for ;transport=xxx
    const char* p = params.c_str();
    while (p && *p) {
        if (*p == ';') ++p;
        if (strncasecmp(p, "transport=", 10) == 0) {
            p += 10;
            size_t l = 0;
            while (p[l] && p[l] != ';') ++l;
            size_t cp = (l < outsz-1) ? l : outsz-1;
            memcpy(out, p, cp); out[cp] = 0;
            // lowercase
            for (size_t i=0; i<cp; ++i) out[i] = (char)tolower((unsigned char)out[i]);
            return;
        }
        while (*p && *p != ';') ++p;
    }
}

// ── parseBracketUri ───────────────────────────────────────────────────────────
// Accepts:  "Display Name" <sip:user@host>  or  <sip:user@host>  or  sip:user@host
Result<SipUri> parseBracketUri(const char* s, size_t len) {
    const char* end = s + len;
    // Skip whitespace
    while (s < end && isspace((unsigned char)*s)) ++s;
    // Find '<'
    const char* lb = (const char*)memchr(s, '<', (size_t)(end-s));
    if (lb) {
        ++lb; // skip '<'
        const char* rb = (const char*)memchr(lb, '>', (size_t)(end-lb));
        if (!rb) return Err::Parse;
        return SipUri::parse(lb, (size_t)(rb - lb));
    }
    // No angle brackets: skip display-name if present (look for whitespace before sip:)
    const char* colon = (const char*)memchr(s, ':', (size_t)(end-s));
    if (!colon) return Err::Parse;
    return SipUri::parse(s, (size_t)(end-s));
}

} // namespace sip
