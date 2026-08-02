// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file SipServer.h
 * @brief SIP server API: registrar, stateful proxy, and B2BUA.
 *
 * Modes:
 * - Proxy mode (`b2buaMode=false`): forwards SIP signaling with Record-Route,
 *   media flows directly between endpoints.
 * - B2BUA mode (`b2buaMode=true`): splits call legs and anchors media on server,
 *   allowing RTP relay and transcoding policy.
 */
#pragma once
#include "Transport.h"
#include "Transaction.h"
#include "SipMessage.h"
#include "UserDb.h"
#include "RegistrarDb.h"
#include "Cdr.h"
#include "Codec.h"
#include "CodecPlugin.h"
#include <functional>
#include <pthread.h>

namespace sip {

/**
 * @brief Runtime configuration for SipServer.
 */
struct ServerConfig {
    /** SIP bind address (empty means wildcard bind). */
    Str<64>  localAddr;         // bind address (empty = 0.0.0.0)
    /** SIP listen port. */
    uint16_t port      = 5060;
    /** Enable UDP transport listener. */
    bool     enableUdp = true;
    /** Enable TCP transport listener. */
    bool     enableTcp = true;

    /** Served SIP domain. */
    Str<64>  domain;            // SIP domain served (e.g. "example.com")
    /** Digest authentication realm. */
    Str<64>  realm;             // Digest auth realm  (usually = domain)

    // Authentication
    /** Require digest auth for REGISTER requests. */
    bool     requireRegAuth  = true;   // digest auth for REGISTER
    /** Require digest auth for INVITE requests. */
    bool     requireCallAuth = false;  // digest auth for INVITE
    /** Secret used to derive challenge nonce values. */
    Str<32>  nonceSecret;              // seed for nonce generation

    // Registration
    /** Default registration expiry. */
    uint32_t defaultExpires = 3600;
    /** Maximum accepted registration expiry. */
    uint32_t maxExpires     = 86400;
    /** Minimum accepted registration expiry. */
    uint32_t minExpires     = 60;

    // Mode
    /** Enable B2BUA mode when true, proxy mode when false. */
    bool     b2buaMode  = false;   // true = B2BUA, false = stateful proxy
    /** Enable call recording hooks (future). */
    bool     recordCalls= false;   // B2BUA: dump RTP to WAV (future)

    // B2BUA RTP relay
    /** Base RTP relay port allocation start. */
    uint16_t rtpBasePort  = 20000;
    /** Advertised relay address for SDP c= lines. */
    Str<64>  rtpLocalAddr;         // IP to put in SDP c= for relay

    // Persistence
    /** Optional on-disk user database path. */
    Str<128> userDbPath;    // path to user DB text file; empty = memory only
    /** Optional CDR CSV output path. */
    Str<128> cdrPath;       // path for CDR CSV file; empty = no CDR

    // Outbound proxy (for calls to foreign domains)
    /** Optional outbound proxy host for foreign domains. */
    Str<64>  outboundProxy;
    /** Outbound proxy SIP port. */
    uint16_t outboundProxyPort = 5060;
    /** Outbound proxy transport protocol. */
    Proto    outboundProto     = Proto::Udp;

    // Optional runtime codec plugins for B2BUA transcoding.
    /** Maximum number of runtime codec plugins. */
    static constexpr size_t MaxCodecPlugins = 8;
    /** Runtime codec plugin .so paths. */
    Str<128> codecPluginPaths[MaxCodecPlugins];
    /** Number of active entries in codecPluginPaths. */
    size_t   codecPluginCount = 0;
};

/**
 * @brief Application callbacks raised by SipServer.
 */
struct ServerCallbacks {
    /** Called on registration state changes. */
    std::function<void(const char* aor, const char* contact, bool registered)> onRegister;

    /** Called on inbound INVITE; return false to reject with 403. */
    std::function<bool(const char* from, const char* to)> onCallAttempt;

    /** Called when a call record terminates (proxy or B2BUA mode). */
    std::function<void(const CdrRecord&)> onCallEnd;

    /** Called for unhandled custom request methods. */
    std::function<void(const SipMessage&)> onUnhandled;
};

/**
 * @brief Per-relay-thread argument block, heap-allocated and owned by the thread.
 *
 * `running` is the authoritative stop-flag.  `closeRtpRelay` sets it to false
 * and immediately closes the socket so any blocked `recv()` wakes up.  The
 * thread calls `delete this` on exit — callers must not touch the block after
 * setting `running = false`.
 */
struct RtpRelayArgs {
    int            srcFd   = -1;
    int            dstFd   = -1;
    char           dstAddr[48] = {};
    uint16_t       dstPort = 0;
    uint8_t        srcPt   = 0;
    uint8_t        dstPt   = 0;
    void*          srcCodec = nullptr;   // ICodec*
    void*          dstCodec = nullptr;   // ICodec*
    volatile bool  running  = true;      ///< set false to request thread exit
};

/**
 * @brief High-level call state for proxy and B2BUA call records.
 */
enum class CallState : uint8_t {
    Calling,     // INVITE forwarded / leg B dialling
    Ringing,     // 180 received from callee
    Connected,   // 200 OK exchanged on both legs
    Terminating, // BYE in progress
    Terminated,
};

/** @brief Proxy mode call record (single forwarded INVITE path). */
struct ProxyCall {
    /** Call-ID associated with this proxy call. */
    CallId   callId;
    /** Current proxy call state. */
    CallState state   = CallState::Calling;
    // Leg A (caller → proxy server transaction)
    /** Inbound server transaction id. */
    TxnId    legATxn  = InvalidTxn;
    /** Caller top Via (used for response forwarding). */
    Via      legAVia;            // caller's top Via (to restore on responses)
    // Leg B (proxy → callee client transaction)
    /** Outbound client transaction id. */
    TxnId    legBTxn  = InvalidTxn;
    /** Caller URI. */
    URI      callerUri;
    /** Callee URI. */
    URI      calleeUri;
    /** Start timestamp in milliseconds. */
    int64_t  startMs  = 0;
    /** Internal slot occupancy marker. */
    bool     used     = false;
};

/** @brief B2BUA mode call record (two independent SIP legs). */
struct B2buaCall {
    /** Canonical call-id for bridged call record. */
    CallId    callId;
    /** Current B2BUA call state. */
    CallState state    = CallState::Calling;
    // Leg A: inbound (caller → us as UAS)
    /** Inbound server transaction id. */
    TxnId     legATxn  = InvalidTxn;
    /** Caller leg call-id. */
    CallId    legACallId;
    /** Local tag for leg A. */
    Tag       legALocalTag;
    /** Remote tag for leg A. */
    Tag       legARemoteTag;
    /** Caller From URI. */
    URI       callerUri;
    /** Caller target/contact URI. */
    URI       callerTarget;        // Contact of caller
    // Leg B: outbound (us as UAC → callee)
    /** Outbound client transaction id. */
    TxnId     legBTxn  = InvalidTxn;
    /** Callee leg call-id. */
    CallId    legBCallId;
    /** Local tag for leg B. */
    Tag       legBLocalTag;
    /** Remote tag for leg B. */
    Tag       legBRemoteTag;
    /** Callee request URI. */
    URI       calleeUri;
    /** Callee contact/target URI. */
    URI       calleeTarget;        // Contact of callee (from 200 OK)
    // RTP relay sockets (B2BUA mode)
    /** Relay socket facing caller RTP stream. */
    int       rtpAFd   = -1;      // relay socket facing caller
    /** Relay socket facing callee RTP stream. */
    int       rtpBFd   = -1;      // relay socket facing callee
    /** Server RTP port toward caller leg. */
    uint16_t  rtpAPort = 0;
    /** Server RTP port toward callee leg. */
    uint16_t  rtpBPort = 0;
    /** Caller RTP IP from SDP. */
    char      callerRtpAddr[48];  // caller RTP address (from SDP)
    /** Caller RTP port from SDP. */
    uint16_t  callerRtpPort = 0;
    /** Caller negotiated payload type. */
    uint8_t   callerPayloadType = 0;
    /** Caller negotiated codec name. */
    Str<24>   callerCodecName;
    /** Callee RTP IP from SDP answer. */
    char      calleeRtpAddr[48];  // callee RTP address (from SDP)
    /** Callee RTP port from SDP answer. */
    uint16_t  calleeRtpPort = 0;
    /** Callee negotiated payload type. */
    uint8_t   calleePayloadType = 0;
    /** Callee negotiated codec name. */
    Str<24>   calleeCodecName;
    /** True while RTP relay loops should run. */
    bool           relayRunning = false;
    /** Relay arg blocks; owned by threads but pointer saved here so
     *  closeRtpRelay can signal them to stop cleanly. */
    RtpRelayArgs*  relayArgAB   = nullptr;   // caller-side → callee-side thread
    RtpRelayArgs*  relayArgBA   = nullptr;   // callee-side → caller-side thread
    // CSeq counters
    /** Outbound leg-B CSeq counter. */
    uint32_t  legBCSeq = 1;
    /** Call start timestamp in milliseconds. */
    int64_t   startMs  = 0;
    /** Connection timestamp in milliseconds (on 200 OK). */
    int64_t   connectMs= 0;
    /** Internal slot occupancy marker. */
    bool      used     = false;
};

/**
 * @brief SIP server facade for registration, routing, and media anchoring.
 */
class SipServer {
public:
    /**
     * @brief Initialize server transport, transaction layer, and callbacks.
     * @param cfg Runtime server configuration.
     * @param cbs Optional callback set.
     * @return true on success.
     */
    bool init(ServerConfig cfg, ServerCallbacks cbs = {});

    /** @brief Stop server and release resources. */
    void shutdown();

    /** @brief Progress timers and cleanup tasks; call periodically (~50ms). */
    void tick();

    // ── User management ───────────────────────────────────────────────────────
    /** @brief Add or update a local user account. */
    bool addUser(const char* username, const char* password,
                 bool canReg = true, bool canCall = true, bool isAdmin = false);

    /** @brief Remove a local user account. */
    bool removeUser(const char* username);

    // ── Diagnostics ───────────────────────────────────────────────────────────
    /** @brief Print aggregate server counters and mode info. */
    void printStats()         const;
    /** @brief Print active registration bindings. */
    void printRegistrations() const;
    /** @brief Print active calls in proxy or B2BUA pool. */
    void printCalls()         const;
    /** @brief Print active codec registry used for transcoding decisions. */
    void printCodecs()        const;

    /** @brief Return count of active registrations. */
    size_t registrationCount() const;
    /** @brief Return count of active call records. */
    size_t activeCallCount()   const;

    /** @brief Mutable user database access. */
    UserDb&       userDb()     { return users_; }
    /** @brief Mutable registrar database access. */
    RegistrarDb&  registrar()  { return reg_; }
    /** @brief Mutable CDR logger access. */
    CdrLogger&    cdr()        { return cdr_; }

private:
    ServerConfig   cfg_;
    ServerCallbacks cbs_;

    Transport        transport_;
    TransactionLayer txn_;
    UserDb           users_;
    RegistrarDb      reg_;
    CdrLogger        cdr_;
    CodecRegistry    codecs_;

    // Call pools
    static constexpr size_t MaxCalls = 256;
    ProxyCall  proxyCalls_[MaxCalls];
    B2buaCall  b2buaCalls_[MaxCalls];

    // Nonce cache (to prevent replay) — simple ring buffer
    static constexpr size_t NonceCache = 64;
    struct NonceEntry { char val[33]; int64_t issueMs; };
    NonceEntry nonceCache_[NonceCache];
    size_t     nonceIdx_ = 0;

    uint16_t   nextRtpPort_ = 20000;
    uint32_t   nextCSeq_    = 1;    // for B2BUA outbound leg

    mutable pthread_mutex_t mu_ = PTHREAD_MUTEX_INITIALIZER;
    struct Guard { pthread_mutex_t& m;
        Guard(pthread_mutex_t& m):m(m){pthread_mutex_lock(&m);}
        ~Guard(){pthread_mutex_unlock(&m);}
    };

    volatile bool running_ = false;

    // Scratch buffers
    char   txBuf_[SIP_MAX_MSG];
    char   sdpBuf_[2048];

    // ── Receive / dispatch ────────────────────────────────────────────────────
    void onRecv(const char* data, size_t len,
                const char* srcHost, uint16_t srcPort, bool isTcp);

    // Transaction callbacks
    void onTxnRequest   (TxnId, const SipMessage&);
    void onTxnResponse  (TxnId, const SipMessage&);
    void onTxnTerminated(TxnId);

    // ── Request handlers ─────────────────────────────────────────────────────
    void handleRegister(TxnId, const SipMessage&,
                        const char* srcHost, uint16_t srcPort, Proto proto);
    void handleInvite  (TxnId, const SipMessage&,
                        const char* srcHost, uint16_t srcPort, Proto proto);
    void handleAck     (const SipMessage&);
    void handleBye     (TxnId, const SipMessage&);
    void handleCancel  (TxnId, const SipMessage&);
    void handleOptions (TxnId, const SipMessage&);
    void handleMessage (TxnId, const SipMessage&);

    // ── Proxy mode ────────────────────────────────────────────────────────────
    void   proxyInvite(TxnId legATxn, const SipMessage& invite,
                       const RegBinding& target, Proto proto);
    void   proxyResponse(ProxyCall& call, const SipMessage& resp);
    ProxyCall* findProxyByLegA(TxnId);
    ProxyCall* findProxyByLegB(TxnId);
    ProxyCall* findProxyByCallId(const CallId&);
    ProxyCall* allocProxy();
    void       freeProxy(ProxyCall&);

    // ── B2BUA mode ────────────────────────────────────────────────────────────
    void      b2buaInvite(TxnId legATxn, const SipMessage& invite,
                          const RegBinding& target, Proto proto);
    void      b2buaLegBResponse(B2buaCall&, const SipMessage&);
    B2buaCall* findB2buaByLegA(TxnId);
    B2buaCall* findB2buaByLegB(TxnId);
    B2buaCall* findB2buaByCallId(const CallId&);
    B2buaCall* allocB2bua();
    void       freeB2bua(B2buaCall&);

    // RTP relay helpers
    uint16_t  allocRtpPort();
    bool      openRtpRelay(B2buaCall& call);
    void      closeRtpRelay(B2buaCall& call);
    static void* rtpRelayThread(void* arg);
    // RtpRelayArgs is defined at namespace scope (see above B2buaCall).

    // ── Auth helpers ─────────────────────────────────────────────────────────
    void  buildChallenge(char* buf, size_t sz, bool proxy);
    bool  checkAuth(const SipMessage& msg, Method m, bool proxy);
    void  issueNonce(char out[33]);
    bool  validateNonce(const char* nonce, int64_t nowMs);

    // ── Helpers ───────────────────────────────────────────────────────────────
    bool   sendResponse(TxnId txn, int code, const char* reason,
                        const char* body = nullptr, size_t blen = 0,
                        const char* ct   = nullptr);
    bool   sendRaw(const char* data, size_t len,
                   const char* host, uint16_t port, Proto proto);
    void   genTag(Tag& t) const;
    void   genBranch(Branch& b) const;
    void   genCallId(CallId& id) const;
    bool   isLocal(const char* domain) const;
    // Build Record-Route for proxy mode
    void   addRecordRoute(SipMessage& msg) const;
    // Rewrite SDP: replace c= and m= port for B2BUA relay
    size_t rewriteSdp(const char* origSdp, size_t origLen,
                      const char* newAddr, uint16_t newPort,
                      char* out, size_t outSz);

    static int64_t nowMs();
    static uint32_t rnd32();
};

} // namespace sip
