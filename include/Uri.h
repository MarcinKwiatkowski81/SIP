// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file Uri.h
 * @brief SIP/SIPS/TEL URI parsing and formatting helpers.
 */
#pragma once
#include "common.h"

namespace sip {

/** @brief Supported URI schemes. */
enum class Scheme : uint8_t { Sip=0, Sips, Tel };

/** @brief Parsed SIP/SIPS/TEL URI model. */
struct SipUri {
    /** URI scheme. */
    Scheme    scheme   = Scheme::Sip;
    /** Userinfo part (empty when URI has no user@). */
    Str<64>   user;          // userinfo (empty if no @)
    /** Hostname or IPv4/IPv6 literal. */
    Str<64>   host;
    /** Explicit URI port; 0 means default by scheme. */
    uint16_t  port     = 0;  // 0 → default
    /** Raw parameter chain beginning with ';' when present. */
    Str<128>  params;        // raw ;key=val chain, including leading ;

    /**
     * @brief Parse URI from a string slice.
     * @param s Input characters.
     * @param len Input length.
     * @return Parsed URI or parse error.
     */
    static Result<SipUri> parse(const char* s, size_t len);
    /** @brief Parse NUL-terminated URI string. */
    static Result<SipUri> parse(const char* s) { return parse(s,strlen(s)); }

    /**
     * @brief Format URI into a buffer.
     * @return Bytes written excluding trailing NUL, or 0 on overflow.
     */
    int format(char* buf, size_t sz) const;

    /** @brief True if URI has a non-empty user component. */
    bool     hasUser()        const { return !user.empty(); }
    /** @brief Effective port (explicit if set, otherwise scheme default). */
    uint16_t effectivePort()  const {
        if (port) return port;
        return scheme == Scheme::Sips ? 5061 : 5060;
    }
    /**
     * @brief Extract `;transport=` parameter as lowercase text.
     * @param out Output buffer.
     * @param outsz Output buffer size.
     */
    void transport(char* out, size_t outsz) const;

    /** @brief Scheme/user/host/effective-port equality check. */
    bool operator==(const SipUri& o) const {
        return scheme==o.scheme && user==o.user &&
               host.eqi(o.host.c_str(), o.host.len) && effectivePort()==o.effectivePort();
    }
};

/**
 * @brief Parse a bare URI or `<uri>` form (display name ignored).
 *
 * Used by From/To/Contact/Route header parsing.
 */
Result<SipUri> parseBracketUri(const char* s, size_t len);

} // namespace sip
