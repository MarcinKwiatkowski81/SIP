// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file SipMessage.h
 * @brief SIP request/response model, parser, and formatter.
 */
#pragma once
#include "common.h"
#include "Uri.h"

namespace sip {

/** @brief SIP methods supported by parser/formatter. */
enum class Method : uint8_t {
    Unknown=0,
    INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS,
    PRACK, UPDATE, REFER, NOTIFY, SUBSCRIBE, INFO,
    MESSAGE,   // RFC 3428
    PUBLISH,   // RFC 3903
};
/** @brief Convert method enum to canonical method name string. */
const char* methodName(Method m);
/** @brief Parse SIP method token into Method enum. */
Method      parseMethod(const char* s, size_t len);

/** @brief Parsed SIP Via header. */
struct Via {
    /** Via host value. */
    Str<64>  host;
    /** Via port value (0 means absent). */
    uint16_t port      = 0;
    /** Branch parameter value. */
    Branch   branch;
    /** Transport token (UDP/TCP/TLS/WS). */
    Str<8>   transport;   // "UDP" "TCP" "TLS" "WS"
    /** True when rport parameter is present. */
    bool     rport     = false;
    /** rport numeric value when known. */
    uint16_t rportVal  = 0;
    /** received parameter value for NAT traversal. */
    Str<40>  received;
    /** True when loose-routing flag is present. */
    bool     lr        = false;

    /**
     * @brief Format Via value.
     * @return Bytes written or 0 on overflow.
     */
    int format(char* buf, size_t sz) const;
    /** @brief Parse one Via value. */
    static Result<Via> parse(const char* s, size_t len);
};

/** @brief Name-addr style header value (From/To/Contact/Route). */
struct NameAddr {
    /** Optional display-name token. */
    Str<64>  displayName;
    /** URI string, e.g. sip:alice@example.com. */
    URI      uri;          // full URI string, e.g. "sip:alice@example.com"
    /** tag parameter value. */
    Tag      tag;
    /** Additional URI/header params. */
    Str<128> params;       // other params (e.g. ;q=0.5)

    /** @brief Parse NameAddr from header value text. */
    static Result<NameAddr> parse(const char* s, size_t len);
    /** @brief Format NameAddr to text form. */
    int format(char* buf, size_t sz, bool withTag=true) const;
};

/** @brief CSeq header value. */
struct CSeq {
    /** Sequence number component. */
    uint32_t seq = 0;
    /** Method component paired with sequence number. */
    Method method = Method::Unknown;
};

/** @brief Fixed-capacity SIP route set. */
struct RouteSet {
    /** Maximum hop entries stored in route set. */
    static constexpr size_t Cap = 8;
    /** Ordered route hop URIs. */
    URI      hops[Cap];
    /** Number of valid hop entries. */
    uint8_t  count = 0;

    /** @brief Clear all route entries. */
    void     clear()                  { count = 0; }
    /** @brief Append route hop entry. */
    bool     push(const char* s, size_t l) {
        if (count >= Cap) return false;
        hops[count++].assign(s, l); return true;
    }
    /** @brief Serialize as comma-separated Route values. */
    int format(char* buf, size_t sz) const;
};

/** @brief Parsed SIP request or response message. */
struct SipMessage {
    // Start-line
    /** True for request start-line, false for response start-line. */
    bool     isRequest   = true;
    /** Request method when isRequest=true. */
    Method   method      = Method::Unknown;
    /** Request URI when isRequest=true. */
    URI      requestUri;
    /** Response status code when isRequest=false. */
    int      statusCode  = 0;
    /** Response reason phrase. */
    Str<64>  reason;

    // Mandatory headers
    /** Via header chain. */
    Via      via[SIP_MAX_VIA];
    /** Number of valid entries in via[]. */
    uint8_t  viaCount    = 0;
    /** From header value. */
    NameAddr from;
    /** To header value. */
    NameAddr to;
    /** Call-ID header value. */
    CallId   callId;
    /** CSeq header value. */
    CSeq     cseq;
    /** Max-Forwards header value. */
    uint32_t maxForwards = 70;

    // Common optional headers
    /** Contact header value. */
    NameAddr contact;
    /** True if Contact header was present. */
    bool     hasContact  = false;
    /** Content-Length header value. */
    uint32_t contentLen  = 0;
    /** Content-Type header value. */
    Str<64>  contentType;
    /** Expires header value. */
    uint32_t expires     = 0;
    /** WWW-Authenticate header value. */
    Str<256> wwwAuth;          // WWW-Authenticate
    /** Proxy-Authenticate header value. */
    Str<256> proxyAuth;        // Proxy-Authenticate
    /** Authorization header value. */
    Str<512> authorization;    // Authorization  (Digest w/ qop=auth ~220-260 chars)
    /** Proxy-Authorization header value. */
    Str<512> proxyAuthorization;
    /** Supported header value. */
    Str<64>  supported;
    /** Require header value. */
    Str<64>  require;
    /** Record-Route raw comma-separated list. */
    Str<256> recordRoute;      // raw comma-list
    /** Route raw comma-separated list. */
    Str<256> route;            // raw comma-list
    /** Allow header value. */
    Str<64>  allow;
    /** User-Agent header value. */
    Str<64>  userAgent;
    /** Server header value. */
    Str<64>  server;
    /** Min-Expires value (-1 means absent). */
    int      minExpires  = -1; // -1 = not present

    // Body (points into the original parse buffer)
    /** Pointer to parsed message body within source buffer. */
    const char* body    = nullptr;
    /** Body length in bytes. */
    size_t      bodyLen = 0;

    // ── Parse ─────────────────────────────────────────────────────────────────
    /**
     * @brief Parse SIP message in-place from buffer.
     *
     * body pointer references memory inside @p buf.
     */
    static Result<SipMessage> parse(const char* buf, size_t len);

    // ── Format ────────────────────────────────────────────────────────────────
    /** @brief Serialize message into SIP wire format text. */
    size_t format(char* buf, size_t sz) const;

    // ── Factories ─────────────────────────────────────────────────────────────
    /** @brief Build response skeleton from incoming request. */
    SipMessage makeResponse(int code, const char* reason) const;

    /** @brief True when message is response-form. */
    bool isResponse()    const { return !isRequest; }
    /** @brief True for provisional (1xx) responses. */
    bool isProvisional() const { return statusCode>=100 && statusCode<200; }
    /** @brief True for final (>=200) responses. */
    bool isFinal()       const { return statusCode>=200; }
    /** @brief True for successful 2xx responses. */
    bool is2xx()         const { return statusCode>=200 && statusCode<300; }
    /** @brief Return first Via header entry. */
    const Via& topVia()  const { return via[0]; }
};

// ── Digest Auth (RFC 7616 / RFC 3261 §22) ─────────────────────────────────────
namespace auth {

/** @brief Parsed digest authentication challenge parameters. */
struct Challenge {
    /** Authentication realm. */
    Str<64>  realm;
    /** Server nonce value. */
    Str<128> nonce;
    /** Digest algorithm token (typically MD5). */
    Str<8>   algorithm;    // "MD5" (default)
    /** Quality-of-protection token (typically auth). */
    Str<16>  qop;          // "auth" or empty
    /** Optional opaque token. */
    Str<64>  opaque;
    /** True if server marks previous nonce as stale. */
    bool     stale = false;
};

/** @brief Parse WWW-Authenticate or Proxy-Authenticate header value. */
Result<Challenge> parseChallenge(const char* s, size_t len);

/**
 * @brief Build Digest Authorization header value.
 * @return Characters written (excluding NUL), or 0 on failure.
 */
int buildAuthHeader(const Challenge& ch, Method method, const char* uri,
                    const char* user, const char* pass,
                    uint32_t nc, char* buf, size_t bufsz);

/** @brief Compute MD5 hex string (32 lowercase chars + NUL). */
void md5Hex(const void* data, size_t len, char out[33]);
/** @brief Compute MD5 of `a:b`. */
void md5HexTwo(const char* a, const char* b, char out[33]);     // MD5(a:b)
/** @brief Compute MD5 of `a:b:c`. */
void md5HexThree(const char* a, const char* b, const char* c, char out[33]); // MD5(a:b:c)

} // namespace auth

} // namespace sip
