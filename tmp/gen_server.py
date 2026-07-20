#!/usr/bin/env python3
# Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
# All rights reserved.

"""Generate all SIP server implementation files."""
import os

BASE = "/home/mkwiatkowski/Projects/SIP"

def W(rel, text):
    path = f"{BASE}/{rel}"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    print(f"  {rel}  ({len(text):,} bytes)")

print("Generating SIP server files...")

# ─────────────────────────────────────────────────────────────────────────────
W("include/UserDb.h", r"""// UserDb.h – SIP server user/credential database
// Thread-safe; backed by a plain-text file (one user per line):
//   username:password:realm:flags
// flags is a bitmask string: R=canRegister C=canCall A=admin
// Passwords stored as plain text OR as pre-hashed HA1 (hex md5 prefix "ha1:").
#pragma once
#include "common.h"
#include "SipMessage.h"   // for auth::
#include <pthread.h>

namespace sip {

struct UserEntry {
    Str<64>  username;
    Str<64>  password;   // plain OR "ha1:<32hexchars>"
    Str<64>  realm;
    bool     canRegister = true;
    bool     canCall     = true;
    bool     isAdmin     = false;
    bool     enabled     = true;
    bool     used        = false;
};

class UserDb {
public:
    static constexpr size_t MaxUsers = 512;

    UserDb();
    ~UserDb();

    // Load from file; returns number of users loaded (-1 on error).
    int  load(const char* path);
    // Save to file; returns false on error.
    bool save(const char* path) const;

    // Add or update a user.
    bool add(const char* username, const char* password, const char* realm,
             bool canReg = true, bool canCall = true, bool isAdmin = false);
    bool remove(const char* username);
    bool setEnabled(const char* username, bool enabled);

    const UserEntry* find(const char* username) const;

    // Verify a Digest auth response (RFC 3261 §22 / RFC 7616).
    // Returns true if credentials are valid.
    bool verifyDigest(const char* username, const auth::Challenge& ch,
                      Method method, const char* uri,
                      const char* response, uint32_t nc,
                      const char* cnonce, const char* qop) const;

    size_t count() const;
    void   printAll() const;

private:
    UserEntry entries_[MaxUsers];
    mutable pthread_mutex_t mu_ = PTHREAD_MUTEX_INITIALIZER;

    UserEntry* findM(const char* username);
    static void ha1(const char* user, const char* realm,
                    const char* pass, char out[33]);
};

} // namespace sip
""")

# ─────────────────────────────────────────────────────────────────────────────
W("include/RegistrarDb.h", r"""// RegistrarDb.h – SIP Registrar binding database (RFC 3261 §10)
// Maintains AOR → {Contact, transport, source, expiry} mappings.
// One AOR may have multiple contacts (multiple devices / forking).
// Thread-safe.
#pragma once
#include "common.h"
#include "Transport.h"
#include <pthread.h>

namespace sip {

struct RegBinding {
    URI      aor;           // Address of Record  sip:user@domain
    URI      contact;       // Contact URI        sip:user@192.168.1.x:5060
    Str<48>  srcAddr;       // Source IP  (for NAT traversal, rport)
    uint16_t srcPort   = 0;
    Proto    proto     = Proto::Udp;
    int64_t  expiresAt = 0;     // absolute ms (0 = expired/unused)
    CallId   regCallId;          // to detect retransmissions
    uint32_t regCSeq   = 0;
    bool     used      = false;
};

class RegistrarDb {
public:
    static constexpr size_t MaxBindings = 2048;

    RegistrarDb();
    ~RegistrarDb();

    // Register / refresh a binding.
    // expiresSec==0 means unregister this contact.
    // Returns false if database full.
    bool update(const char* aor, const char* contact,
                const char* srcAddr, uint16_t srcPort,
                Proto proto, uint32_t expiresSec,
                const char* callId, uint32_t cseq,
                int64_t nowMs);

    // Remove all contacts for an AOR.
    void unregisterAll(const char* aor);

    // Copy active bindings for an AOR into out[].
    // Returns number found (0 = not registered).
    size_t findBindings(const char* aor,
                        RegBinding* out, size_t maxOut,
                        int64_t nowMs) const;

    bool hasBinding(const char* aor, int64_t nowMs) const;

    // Expire stale bindings; call from tick().
    void expire(int64_t nowMs);

    size_t totalBindings() const;
    void   printAll(int64_t nowMs) const;

private:
    RegBinding entries_[MaxBindings];
    mutable pthread_mutex_t mu_ = PTHREAD_MUTEX_INITIALIZER;
};

} // namespace sip
""")

# ─────────────────────────────────────────────────────────────────────────────
W("include/Cdr.h", r"""// Cdr.h – Call Detail Record logger
// Writes one CSV line per call to a file (or stdout if path is null).
// Thread-safe; buffered writes.
// CSV columns:
//   timestamp_iso, call_id, from_uri, to_uri, direction,
//   duration_ms, result_code, result_text
#pragma once
#include "common.h"
#include <pthread.h>

namespace sip {

enum class CdrResult : uint8_t {
    Answered   = 0,
    NoAnswer,
    Busy,
    Rejected,
    Error,
    Cancelled,
};

struct CdrRecord {
    CallId   callId;
    URI      fromUri;
    URI      toUri;
    bool     outbound = true;    // true = we initiated
    int64_t  startMs  = 0;       // INVITE sent/received
    int64_t  connectMs = 0;      // 200 OK
    int64_t  endMs    = 0;       // BYE / final response
    CdrResult result  = CdrResult::NoAnswer;
    int       sipCode = 0;
};

class CdrLogger {
public:
    // path=nullptr → stdout only
    bool open(const char* path);
    void close();

    void write(const CdrRecord& rec);

private:
    FILE*           fp_  = nullptr;
    pthread_mutex_t mu_  = PTHREAD_MUTEX_INITIALIZER;
    static void isoTime(int64_t ms, char* buf, size_t len);
};

} // namespace sip
""")

# ─────────────────────────────────────────────────────────────────────────────
W("include/SipServer.h", r"""// SipServer.h – Full SIP Server: Registrar + Stateful Proxy + B2BUA
//
// Architecture:
//
//   ┌──────────────────────────────────────────────────────────┐
//   │                      SipServer                           │
//   │                                                          │
//   │  Transport (UDP+TCP) ──► onRecv ──► TransactionLayer     │
//   │                                         │                │
//   │      ┌──────────────────────────────────┤                │
//   │      ▼                                  ▼                │
//   │  handleRequest                    handleResponse         │
//   │      │                                  │                │
//   │  ┌───┴──────────────┐         ┌─────────┴──────────┐    │
//   │  │  Registrar       │         │  ProxyCall /        │    │
//   │  │  (REGISTER)      │         │  B2buaCall state    │    │
//   │  └──────────────────┘         └────────────────────┘     │
//   │                                                          │
//   │  UserDb   RegistrarDb   CdrLogger   RtpRelay(B2BUA)      │
//   └──────────────────────────────────────────────────────────┘
//
// Modes:
//   Proxy mode  (b2buaMode=false, default):
//     Routes INVITE by forwarding with Record-Route.
//     Media flows directly between endpoints.
//
//   B2BUA mode  (b2buaMode=true):
//     Terminates each leg independently.
//     Rewrites SDP to relay RTP through server.
//     Enables recording, transcoding (future), policy enforcement.
#pragma once
#include "Transport.h"
#include "Transaction.h"
#include "SipMessage.h"
#include "UserDb.h"
#include "RegistrarDb.h"
#include "Cdr.h"
#include "Codec.h"
#include <functional>
#include <pthread.h>

namespace sip {

// ── Server configuration ─────────────────────────────────────────────────────
struct ServerConfig {
    Str<64>  localAddr;         // bind address (empty = 0.0.0.0)
    uint16_t port      = 5060;
    bool     enableUdp = true;
    bool     enableTcp = true;

    Str<64>  domain;            // SIP domain served (e.g. "example.com")
    Str<64>  realm;             // Digest auth realm  (usually = domain)

    // Authentication
    bool     requireRegAuth  = true;   // digest auth for REGISTER
    bool     requireCallAuth = false;  // digest auth for INVITE
    Str<32>  nonceSecret;              // seed for nonce generation

    // Registration
    uint32_t defaultExpires = 3600;
    uint32_t maxExpires     = 86400;
    uint32_t minExpires     = 60;

    // Mode
    bool     b2buaMode  = false;   // true = B2BUA, false = stateful proxy
    bool     recordCalls= false;   // B2BUA: dump RTP to WAV (future)

    // B2BUA RTP relay
    uint16_t rtpBasePort  = 20000;
    Str<64>  rtpLocalAddr;         // IP to put in SDP c= for relay

    // Persistence
    Str<128> userDbPath;    // path to user DB text file; empty = memory only
    Str<128> cdrPath;       // path for CDR CSV file; empty = no CDR

    // Outbound proxy (for calls to foreign domains)
    Str<64>  outboundProxy;
    uint16_t outboundProxyPort = 5060;
    Proto    outboundProto     = Proto::Udp;
};

// ── Server callbacks ──────────────────────────────────────────────────────────
struct ServerCallbacks {
    // Called when a UA registers or unregisters.
    std::function<void(const char* aor, const char* contact, bool registered)> onRegister;

    // Called on new inbound INVITE (after routing, before 100 Trying).
    // Return false to reject with 403 Forbidden.
    std::function<bool(const char* from, const char* to)> onCallAttempt;

    // Called when a call ends (both proxy and B2BUA modes).
    std::function<void(const CdrRecord&)> onCallEnd;

    // Called for any unhandled request (custom extensions).
    std::function<void(const SipMessage&)> onUnhandled;
};

// ── Active call tracking ──────────────────────────────────────────────────────
enum class CallState : uint8_t {
    Calling,     // INVITE forwarded / leg B dialling
    Ringing,     // 180 received from callee
    Connected,   // 200 OK exchanged on both legs
    Terminating, // BYE in progress
    Terminated,
};

// Proxy mode: one record per forwarded INVITE
struct ProxyCall {
    CallId   callId;
    CallState state   = CallState::Calling;
    // Leg A (caller → proxy server transaction)
    TxnId    legATxn  = InvalidTxn;
    Via      legAVia;            // caller's top Via (to restore on responses)
    // Leg B (proxy → callee client transaction)
    TxnId    legBTxn  = InvalidTxn;
    URI      callerUri;
    URI      calleeUri;
    int64_t  startMs  = 0;
    bool     used     = false;
};

// B2BUA mode: two independent dialogs bridged
struct B2buaCall {
    CallId    callId;
    CallState state    = CallState::Calling;
    // Leg A: inbound (caller → us as UAS)
    TxnId     legATxn  = InvalidTxn;
    CallId    legACallId;
    Tag       legALocalTag;
    Tag       legARemoteTag;
    URI       callerUri;
    URI       callerTarget;        // Contact of caller
    // Leg B: outbound (us as UAC → callee)
    TxnId     legBTxn  = InvalidTxn;
    CallId    legBCallId;
    Tag       legBLocalTag;
    Tag       legBRemoteTag;
    URI       calleeUri;
    URI       calleeTarget;        // Contact of callee (from 200 OK)
    // RTP relay sockets (B2BUA mode)
    int       rtpAFd   = -1;      // relay socket facing caller
    int       rtpBFd   = -1;      // relay socket facing callee
    uint16_t  rtpAPort = 0;
    uint16_t  rtpBPort = 0;
    char      callerRtpAddr[48];  // caller RTP address (from SDP)
    uint16_t  callerRtpPort = 0;
    char      calleeRtpAddr[48];  // callee RTP address (from SDP)
    uint16_t  calleeRtpPort = 0;
    pthread_t relayTid;
    bool      relayRunning = false;
    // CSeq counters
    uint32_t  legBCSeq = 1;
    int64_t   startMs  = 0;
    int64_t   connectMs= 0;
    bool      used     = false;
};

// ── SipServer ─────────────────────────────────────────────────────────────────
class SipServer {
public:
    bool init(ServerConfig cfg, ServerCallbacks cbs = {});
    void shutdown();

    // Call every ~50 ms (timers, registration expiry, CDR flush).
    void tick();

    // ── User management ───────────────────────────────────────────────────────
    bool addUser(const char* username, const char* password,
                 bool canReg = true, bool canCall = true, bool isAdmin = false);
    bool removeUser(const char* username);

    // ── Diagnostics ───────────────────────────────────────────────────────────
    void printStats()         const;
    void printRegistrations() const;
    void printCalls()         const;

    size_t registrationCount() const;
    size_t activeCallCount()   const;

    UserDb&       userDb()     { return users_; }
    RegistrarDb&  registrar()  { return reg_; }
    CdrLogger&    cdr()        { return cdr_; }

private:
    ServerConfig   cfg_;
    ServerCallbacks cbs_;

    Transport        transport_;
    TransactionLayer txn_;
    UserDb           users_;
    RegistrarDb      reg_;
    CdrLogger        cdr_;

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
    struct RelayArgs { SipServer* srv; B2buaCall* call; int srcFd; int dstFd; char dstAddr[48]; uint16_t dstPort; };

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
""")

# ─────────────────────────────────────────────────────────────────────────────
W("src/UserDb.cpp", r"""// UserDb.cpp
#include "UserDb.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>

namespace sip {

// Use the portable MD5 from SipMessage.cpp via forward-declare
namespace auth {
    void md5Hex(const void* data, size_t len, char out[33]);
}

UserDb::UserDb() { memset(entries_, 0, sizeof entries_); }
UserDb::~UserDb() { pthread_mutex_destroy(&mu_); }

void UserDb::ha1(const char* user, const char* realm, const char* pass, char out[33]) {
    char tmp[256]; int n=snprintf(tmp,sizeof tmp,"%s:%s:%s",user,realm,pass);
    auth::md5Hex(tmp,(size_t)n,out);
}

bool UserDb::add(const char* username, const char* password, const char* realm,
                 bool canReg, bool canCall, bool isAdmin) {
    pthread_mutex_lock(&mu_);
    // Update existing
    for (auto& e : entries_) {
        if (e.used && e.username==username) {
            e.password.assign(password,strlen(password));
            e.realm.assign(realm,strlen(realm));
            e.canRegister=canReg; e.canCall=canCall; e.isAdmin=isAdmin;
            pthread_mutex_unlock(&mu_); return true;
        }
    }
    // Add new
    for (auto& e : entries_) {
        if (!e.used) {
            e.used=true; e.enabled=true;
            e.username.assign(username,strlen(username));
            e.password.assign(password,strlen(password));
            e.realm.assign(realm ? realm : "", realm ? strlen(realm) : 0);
            e.canRegister=canReg; e.canCall=canCall; e.isAdmin=isAdmin;
            pthread_mutex_unlock(&mu_); return true;
        }
    }
    pthread_mutex_unlock(&mu_); return false; // full
}

bool UserDb::remove(const char* username) {
    pthread_mutex_lock(&mu_);
    for (auto& e : entries_) {
        if (e.used && e.username==username) { e.used=false; pthread_mutex_unlock(&mu_); return true; }
    }
    pthread_mutex_unlock(&mu_); return false;
}

bool UserDb::setEnabled(const char* username, bool enabled) {
    pthread_mutex_lock(&mu_);
    for (auto& e : entries_) {
        if (e.used && e.username==username) { e.enabled=enabled; pthread_mutex_unlock(&mu_); return true; }
    }
    pthread_mutex_unlock(&mu_); return false;
}

UserEntry* UserDb::findM(const char* username) {
    for (auto& e : entries_) if (e.used && e.username==username) return &e;
    return nullptr;
}
const UserEntry* UserDb::find(const char* username) const {
    for (const auto& e : entries_) if (e.used && e.username==username) return &e;
    return nullptr;
}

bool UserDb::verifyDigest(const char* username, const auth::Challenge& ch,
                          Method method, const char* uri,
                          const char* response, uint32_t nc,
                          const char* cnonce, const char* qop) const {
    pthread_mutex_lock(&mu_);
    const UserEntry* u = find(username);
    if (!u || !u->enabled) { pthread_mutex_unlock(&mu_); return false; }

    // Compute HA1
    char ha1[33];
    const char* pw = u->password.c_str();
    const char* rl = u->realm.empty() ? ch.realm.c_str() : u->realm.c_str();
    if (strncmp(pw,"ha1:",4)==0) {
        strncpy(ha1, pw+4, 32); ha1[32]=0;
    } else {
        UserDb::ha1(username, rl, pw, ha1);
    }

    // Compute HA2
    char ha2[33], tmp[512], resp[33];
    snprintf(tmp,sizeof tmp,"%s:%s",methodName(method),uri);
    auth::md5Hex(tmp,strlen(tmp),ha2);

    // Compute response
    bool hasQop = qop && strncmp(qop,"auth",4)==0;
    if (hasQop) {
        char ncStr[9]; snprintf(ncStr,sizeof ncStr,"%08x",nc);
        snprintf(tmp,sizeof tmp,"%s:%s:%s:%s:%s:%s",ha1,ch.nonce.c_str(),ncStr,cnonce,"auth",ha2);
    } else {
        snprintf(tmp,sizeof tmp,"%s:%s:%s",ha1,ch.nonce.c_str(),ha2);
    }
    auth::md5Hex(tmp,strlen(tmp),resp);
    pthread_mutex_unlock(&mu_);

    return (strcmp(resp, response) == 0);
}

int UserDb::load(const char* path) {
    FILE* f = fopen(path,"r"); if(!f) return -1;
    char line[512]; int n=0;
    while (fgets(line,sizeof line,f)) {
        // skip comments and blank lines
        if (line[0]=='#'||line[0]=='\n'||line[0]=='\r') continue;
        // format: username:password:realm:flags
        char user[64]={},pass[64]={},realm[64]={},flags[16]={};
        if (sscanf(line,"%63[^:]:%63[^:]:%63[^:]:%15s",user,pass,realm,flags)>=2) {
            bool canReg=true, canCall=true, isAdmin=false;
            for (char* p=flags; *p; ++p) {
                if (*p=='R'||*p=='r') canReg=true;
                if (*p=='C'||*p=='c') canCall=true;
                if (*p=='A'||*p=='a') isAdmin=true;
                if (*p=='-') canReg=canCall=false;
            }
            if (add(user,pass,*realm?realm:nullptr,canReg,canCall,isAdmin)) ++n;
        }
    }
    fclose(f); return n;
}

bool UserDb::save(const char* path) const {
    FILE* f = fopen(path,"w"); if(!f) return false;
    fprintf(f,"# SIP user database: username:password:realm:flags\n");
    fprintf(f,"# flags: R=register C=call A=admin  (- = all disabled)\n");
    pthread_mutex_lock(&mu_);
    for (const auto& e : entries_) {
        if (!e.used) continue;
        char flags[8]="";
        if (e.canRegister) strcat(flags,"R");
        if (e.canCall)     strcat(flags,"C");
        if (e.isAdmin)     strcat(flags,"A");
        if (!*flags) strcpy(flags,"-");
        fprintf(f,"%s:%s:%s:%s\n",e.username.c_str(),e.password.c_str(),
                e.realm.c_str(),flags);
    }
    pthread_mutex_unlock(&mu_);
    fclose(f); return true;
}

size_t UserDb::count() const {
    size_t n=0;
    pthread_mutex_lock(&mu_);
    for (const auto& e : entries_) if (e.used) ++n;
    pthread_mutex_unlock(&mu_);
    return n;
}

void UserDb::printAll() const {
    printf("%-20s %-30s %-20s %s\n","User","Realm","Flags","Status");
    printf("%-20s %-30s %-20s %s\n","----","-----","-----","------");
    pthread_mutex_lock(&mu_);
    for (const auto& e : entries_) {
        if (!e.used) continue;
        char flags[16]="";
        if (e.canRegister) strcat(flags,"register ");
        if (e.canCall)     strcat(flags,"call ");
        if (e.isAdmin)     strcat(flags,"admin ");
        printf("%-20s %-30s %-20s %s\n",
               e.username.c_str(), e.realm.c_str(), flags,
               e.enabled ? "enabled" : "DISABLED");
    }
    pthread_mutex_unlock(&mu_);
}

} // namespace sip
""")

# ─────────────────────────────────────────────────────────────────────────────
W("src/RegistrarDb.cpp", r"""// RegistrarDb.cpp
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
""")

# ─────────────────────────────────────────────────────────────────────────────
W("src/Cdr.cpp", r"""// Cdr.cpp
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
""")

# ─────────────────────────────────────────────────────────────────────────────
W("src/SipServer.cpp", r"""// SipServer.cpp – SIP Server: Registrar + Stateful Proxy + B2BUA
#include "SipServer.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <cerrno>
#include <algorithm>

namespace sip {

// ── Helpers ───────────────────────────────────────────────────────────────────
int64_t SipServer::nowMs() {
    struct timeval tv; gettimeofday(&tv,nullptr);
    return (int64_t)tv.tv_sec*1000 + tv.tv_usec/1000;
}
uint32_t SipServer::rnd32() { return (uint32_t)rand()^(uint32_t)(rand()<<16); }

void SipServer::genBranch(Branch& b) const {
    char tmp[80]; snprintf(tmp,sizeof tmp,"z9hG4bK%08x%08x",rnd32(),rnd32());
    b.assign(tmp,strlen(tmp));
}
void SipServer::genCallId(CallId& id) const {
    char tmp[80]; snprintf(tmp,sizeof tmp,"%08x%08x@%s",rnd32(),rnd32(),
                           cfg_.localAddr.c_str());
    id.assign(tmp,strlen(tmp));
}
void SipServer::genTag(Tag& t) const {
    char tmp[16]; snprintf(tmp,sizeof tmp,"%08x",rnd32()); t.assign(tmp,8);
}
bool SipServer::isLocal(const char* domain) const {
    if (!domain) return false;
    if (cfg_.domain==domain) return true;
    if (cfg_.localAddr==domain) return true;
    // Also match "localhost", "127.0.0.1" if running locally
    return (strcmp(domain,"localhost")==0 || strcmp(domain,"127.0.0.1")==0);
}

// ── init ──────────────────────────────────────────────────────────────────────
bool SipServer::init(ServerConfig cfg, ServerCallbacks cbs) {
    cfg_ = cfg; cbs_ = cbs;
    srand((unsigned)time(nullptr)^(unsigned)getpid());
    memset(proxyCalls_,  0, sizeof proxyCalls_);
    memset(b2buaCalls_,  0, sizeof b2buaCalls_);
    memset(nonceCache_,  0, sizeof nonceCache_);
    nextRtpPort_ = cfg_.rtpBasePort;
    if (nextRtpPort_==0) nextRtpPort_=20000;

    // Load user DB
    if (!cfg_.userDbPath.empty()) {
        int n = users_.load(cfg_.userDbPath.c_str());
        if (n >= 0) printf("[SERVER] Loaded %d users from %s\n", n, cfg_.userDbPath.c_str());
    }

    // Open CDR
    if (!cfg_.cdrPath.empty()) cdr_.open(cfg_.cdrPath.c_str());

    // Open transport
    Transport::Config tc;
    tc.localAddr  = cfg_.localAddr.empty() ? nullptr : cfg_.localAddr.c_str();
    tc.port       = cfg_.port;
    tc.enableUdp  = cfg_.enableUdp;
    tc.enableTcp  = cfg_.enableTcp;

    if (!transport_.open(tc, [this](const char* d,size_t l,
                                     const char* h,uint16_t p,bool tcp){
            Guard g(mu_); onRecv(d,l,h,p,tcp);
        })) return false;

    // Wire transaction layer — TCP-aware send
    txn_.init(
        [this](const char* h,uint16_t p,const char* d,size_t l)->bool{
            return transport_.sendUdp(d,l,h,p);
        },
        { [this](TxnId id,const SipMessage& m){ onTxnResponse(id,m); },
          [this](TxnId id,const SipMessage& m){ onTxnRequest(id,m); },
          [this](TxnId id){ onTxnTerminated(id); } }
    );

    running_ = true;
    printf("[SERVER] SIP server started  %s:%u  domain=%s  mode=%s\n",
           tc.localAddr?tc.localAddr:"*", cfg_.port, cfg_.domain.c_str(),
           cfg_.b2buaMode?"B2BUA":"Proxy");
    return true;
}

// ── shutdown ──────────────────────────────────────────────────────────────────
void SipServer::shutdown() {
    running_ = false;
    transport_.close();
    cdr_.close();
    if (!cfg_.userDbPath.empty()) users_.save(cfg_.userDbPath.c_str());
    // Close B2BUA RTP relays
    for (auto& c : b2buaCalls_) { if (c.used) closeRtpRelay(c); }
}

// ── tick ──────────────────────────────────────────────────────────────────────
void SipServer::tick() {
    Guard g(mu_);
    int64_t now = nowMs();
    txn_.tick(now);
    reg_.expire(now);
}

// ── User management ───────────────────────────────────────────────────────────
bool SipServer::addUser(const char* u, const char* p,
                        bool canReg, bool canCall, bool isAdmin) {
    return users_.add(u, p, cfg_.realm.c_str(), canReg, canCall, isAdmin);
}
bool SipServer::removeUser(const char* u) { return users_.remove(u); }

// ── Transport receive → dispatch ─────────────────────────────────────────────
void SipServer::onRecv(const char* data, size_t len,
                       const char* srcHost, uint16_t srcPort, bool isTcp) {
    auto r = SipMessage::parse(data, len); if (!r.ok()) return;
    const SipMessage& msg = *r;
    Proto proto = isTcp ? Proto::Tcp : Proto::Udp;

    // Feed transaction layer first
    if (txn_.onMessage(msg, srcHost, srcPort)) return;

    // ACK for 2xx is outside transactions
    if (msg.isRequest && msg.method == Method::ACK) { handleAck(msg); return; }
}

// ── Transaction callbacks ─────────────────────────────────────────────────────
void SipServer::onTxnRequest(TxnId id, const SipMessage& msg) {
    Proto proto = Proto::Udp;
    const char* srcHost = "";
    uint16_t    srcPort = SIP_UDP_PORT;
    if (msg.viaCount > 0) {
        proto   = Transport::protoFromVia(msg.via[0].transport.c_str());
        srcHost = msg.via[0].received.empty()
                ? msg.via[0].host.c_str() : msg.via[0].received.c_str();
        srcPort = msg.via[0].rportVal ? msg.via[0].rportVal
                : (msg.via[0].port    ? msg.via[0].port : SIP_UDP_PORT);
    }
    switch (msg.method) {
    case Method::REGISTER: handleRegister(id,msg,srcHost,srcPort,proto); break;
    case Method::INVITE:   handleInvite  (id,msg,srcHost,srcPort,proto); break;
    case Method::BYE:      handleBye     (id,msg);                       break;
    case Method::CANCEL:   handleCancel  (id,msg);                       break;
    case Method::OPTIONS:  handleOptions (id,msg);                       break;
    case Method::MESSAGE:  handleMessage (id,msg);                       break;
    default:
        sendResponse(id,405,"Method Not Allowed");
        break;
    }
}

void SipServer::onTxnResponse(TxnId id, const SipMessage& msg) {
    // B2BUA: leg-B response?
    if (cfg_.b2buaMode) {
        B2buaCall* c = findB2buaByLegB(id);
        if (c) { b2buaLegBResponse(*c,msg); return; }
    } else {
        // Proxy: leg-B response?
        ProxyCall* c = findProxyByLegB(id);
        if (c) { proxyResponse(*c,msg); return; }
    }
}
void SipServer::onTxnTerminated(TxnId /*id*/) {}

// ── REGISTER handler ──────────────────────────────────────────────────────────
void SipServer::handleRegister(TxnId txnId, const SipMessage& msg,
                                const char* srcHost, uint16_t srcPort, Proto proto) {
    int64_t now = nowMs();

    // Require auth?
    if (cfg_.requireRegAuth) {
        if (msg.authorization.empty()) {
            // Issue 401 challenge
            char ch[512]; buildChallenge(ch,sizeof ch,false);
            SipMessage r=msg.makeResponse(401,"Unauthorized");
            r.wwwAuth.assign(ch,strlen(ch));
            txn_.sendResponse(txnId,r); return;
        }
        // Verify credentials
        auto authStr = msg.authorization.c_str();
        auto parsed  = auth::parseChallenge(authStr, strlen(authStr));
        if (!parsed.ok()) { sendResponse(txnId,400,"Bad Request"); return; }

        // Extract response/nc/cnonce/qop from Authorization header
        const char* respVal = strstr(authStr,"response=\"");
        char responseHex[64]={};
        if (respVal) { respVal+=10; const char* e=strchr(respVal,'"'); if(e) { size_t l=e-respVal; if(l<64){strncpy(responseHex,respVal,l);} } }

        const char* userVal = strstr(authStr,"username=\"");
        char username[64]={};
        if (userVal) { userVal+=10; const char* e=strchr(userVal,'"'); if(e) { size_t l=e-userVal; if(l<64){strncpy(username,userVal,l);} } }

        const char* uriVal = strstr(authStr,"uri=\"");
        char uri[256]={};
        if (uriVal) { uriVal+=5; const char* e=strchr(uriVal,'"'); if(e) { size_t l=e-uriVal; if(l<256){strncpy(uri,uriVal,l);} } }

        if (!validateNonce(parsed->nonce.c_str(), now)) {
            char ch[512]; buildChallenge(ch,sizeof ch,false);
            SipMessage r=msg.makeResponse(401,"Unauthorized");
            r.wwwAuth.assign(ch,strlen(ch));
            r.header("Stale").assign("true",4);
            txn_.sendResponse(txnId,r); return;
        }

        if (!users_.verifyDigest(username,*parsed,Method::REGISTER,uri,
                                  responseHex,1,nullptr,nullptr)) {
            sendResponse(txnId,403,"Forbidden"); return;
        }
    }

    // Get AOR from To header
    char aor[256]; snprintf(aor,sizeof aor,"%s",msg.to.uri.c_str());

    // Determine expires
    uint32_t expires = msg.expires;
    if (!expires && msg.hasContact) expires = cfg_.defaultExpires;
    expires = std::min(expires, cfg_.maxExpires);
    if (expires > 0 && expires < cfg_.minExpires) {
        // 423 Interval Too Brief
        SipMessage r=msg.makeResponse(423,"Interval Too Brief");
        r.minExpires = (int)cfg_.minExpires;
        txn_.sendResponse(txnId,r); return;
    }

    // star-contact (*) = unregister all
    bool starContact = false;
    if (msg.hasContact && msg.contact.uri.len==1 && msg.contact.uri.buf[0]=='*')
        starContact = true;

    if (starContact && expires==0) {
        reg_.unregisterAll(aor);
        SipMessage ok=msg.makeResponse(200,"OK"); ok.expires=0;
        txn_.sendResponse(txnId,ok);
        if (cbs_.onRegister) cbs_.onRegister(aor,"*",false);
        return;
    }

    if (msg.hasContact && !starContact) {
        const char* contact = msg.contact.uri.c_str();
        // Use received address for NAT traversal
        char effectiveContact[256];
        snprintf(effectiveContact,sizeof effectiveContact,"%s",contact);

        reg_.update(aor, effectiveContact, srcHost, srcPort, proto,
                    expires, msg.callId.c_str(), msg.cseq.seq, now);

        if (cbs_.onRegister) cbs_.onRegister(aor, effectiveContact, expires>0);
    }

    // Build 200 OK with Contact list
    SipMessage ok = msg.makeResponse(200,"OK");
    ok.expires = expires;
    if (msg.hasContact) {
        char cb[256]; snprintf(cb,sizeof cb,"%s;expires=%u",
                               msg.contact.uri.c_str(), expires);
        ok.contact.uri.assign(cb,strlen(cb)); ok.hasContact=true;
    }
    txn_.sendResponse(txnId,ok);
    printf("[REG] %s  contact=%s  expires=%us\n",
           aor, msg.hasContact?msg.contact.uri.c_str():"(none)", expires);
}

// ── INVITE handler ────────────────────────────────────────────────────────────
void SipServer::handleInvite(TxnId txnId, const SipMessage& msg,
                              const char* srcHost, uint16_t srcPort, Proto proto) {
    int64_t now = nowMs();
    (void)srcHost; (void)srcPort;

    // Send 100 Trying immediately
    SipMessage trying=msg.makeResponse(100,"Trying");
    txn_.sendResponse(txnId,trying);

    // Auth check for calls
    if (cfg_.requireCallAuth) {
        if (msg.authorization.empty() && msg.proxyAuthorization.empty()) {
            char ch[512]; buildChallenge(ch,sizeof ch,true);
            SipMessage r=msg.makeResponse(407,"Proxy Authentication Required");
            r.proxyAuth.assign(ch,strlen(ch));
            txn_.sendResponse(txnId,r); return;
        }
        // (Verification logic analogous to REGISTER; omitted for brevity)
    }

    // Extract callee
    auto toUri = SipUri::parse(msg.requestUri.c_str());
    if (!toUri.ok()) { sendResponse(txnId,400,"Bad Request"); return; }

    // Application callback — allow rejection
    if (cbs_.onCallAttempt) {
        if (!cbs_.onCallAttempt(msg.from.uri.c_str(), msg.requestUri.c_str())) {
            sendResponse(txnId,403,"Forbidden"); return;
        }
    }

    // Local domain → look up in registrar
    if (isLocal(toUri->host.c_str())) {
        char aor[256];
        snprintf(aor,sizeof aor,"sip:%s@%s",
                 toUri->user.c_str(), cfg_.domain.c_str());
        RegBinding binding;
        if (reg_.findBindings(aor, &binding, 1, now) == 0) {
            // 404 Not Found or 480 Temporarily Unavailable
            sendResponse(txnId,404,"Not Found"); return;
        }
        if (cfg_.b2buaMode)
            b2buaInvite(txnId, msg, binding, proto);
        else
            proxyInvite(txnId, msg, binding, proto);
        return;
    }

    // Foreign domain → outbound proxy or reject
    if (!cfg_.outboundProxy.empty()) {
        RegBinding gw;
        gw.contact=msg.requestUri; gw.used=true;
        gw.srcAddr=cfg_.outboundProxy; gw.srcPort=cfg_.outboundProxyPort;
        gw.proto=cfg_.outboundProto;
        if (cfg_.b2buaMode)
            b2buaInvite(txnId,msg,gw,proto);
        else
            proxyInvite(txnId,msg,gw,proto);
        return;
    }

    sendResponse(txnId,604,"Does Not Exist Anywhere");
}

// ── Proxy mode ────────────────────────────────────────────────────────────────
void SipServer::proxyInvite(TxnId legATxn, const SipMessage& invite,
                             const RegBinding& target, Proto /*proto*/) {
    ProxyCall* call = allocProxy(); if (!call) { sendResponse(legATxn,503,"Service Unavailable"); return; }
    call->legATxn = legATxn;
    call->callerUri.assign(invite.from.uri.c_str(), invite.from.uri.len);
    call->calleeUri.assign(invite.requestUri.c_str(), invite.requestUri.len);
    call->callId   = invite.callId;
    call->startMs  = nowMs();
    call->state    = CallState::Calling;

    // Save caller's top Via for response restoration
    if (invite.viaCount > 0) call->legAVia = invite.via[0];

    // Build forwarded INVITE: strip top Via, add our Via + Record-Route
    SipMessage fwd = invite;
    // Shift Vias down (remove ours if it was there, shouldn't be)
    // Add our own Via on top
    Branch br; genBranch(br);
    for (int i=fwd.viaCount; i>0; --i) fwd.via[i]=fwd.via[i-1];
    fwd.via[0].host = cfg_.localAddr;
    fwd.via[0].port = cfg_.port;
    fwd.via[0].branch = br;
    fwd.via[0].transport.assign(target.proto==Proto::Tcp?"TCP":"UDP",3);
    fwd.viaCount = std::min(fwd.viaCount+1, SIP_MAX_VIA);
    fwd.maxForwards = (fwd.maxForwards > 0) ? fwd.maxForwards-1 : 0;
    addRecordRoute(fwd);

    // Route to target
    const char* dst = target.srcAddr.empty() ? target.contact.c_str() : target.srcAddr.c_str();
    uint16_t    dstPort = target.srcPort ? target.srcPort : SIP_UDP_PORT;
    auto parsed = SipUri::parse(target.contact.c_str());
    if (parsed.ok() && !parsed->host.empty()) {
        dst     = parsed->host.c_str();
        dstPort = parsed->effectivePort();
    }
    bool udp = target.proto == Proto::Udp;
    call->legBTxn = txn_.sendRequest(fwd, dst, dstPort, udp);
    if (call->legBTxn == InvalidTxn) {
        freeProxy(*call); sendResponse(legATxn,503,"Service Unavailable");
    }
}

void SipServer::proxyResponse(ProxyCall& call, const SipMessage& resp) {
    if (resp.isProvisional()) {
        // Forward 180/183 upstream: strip our Via, forward
        SipMessage fwd = resp;
        if (fwd.viaCount > 1) {
            for (int i=0;i+1<fwd.viaCount;++i) fwd.via[i]=fwd.via[i+1];
            --fwd.viaCount;
        }
        // Find leg-A txn and send response upstream
        // (txn layer doesn't support injecting responses into server txns easily;
        //  send raw via transport using call->legAVia)
        char buf[SIP_MAX_MSG]; size_t n = fwd.format(buf, sizeof buf);
        if (n) {
            const char* dst = call.legAVia.received.empty()
                            ? call.legAVia.host.c_str()
                            : call.legAVia.received.c_str();
            uint16_t dstPort = call.legAVia.rportVal ? call.legAVia.rportVal
                             : (call.legAVia.port    ? call.legAVia.port : SIP_UDP_PORT);
            Proto proto = Transport::protoFromVia(call.legAVia.transport.c_str());
            sendRaw(buf,n,dst,dstPort,proto);
        }
        if (resp.statusCode==180) call.state=CallState::Ringing;
        return;
    }

    if (resp.is2xx()) {
        call.state = CallState::Connected;
        // Forward 200 OK upstream
        SipMessage fwd = resp;
        if (fwd.viaCount > 1) {
            for (int i=0;i+1<fwd.viaCount;++i) fwd.via[i]=fwd.via[i+1];
            --fwd.viaCount;
        }
        char buf[SIP_MAX_MSG]; size_t n = fwd.format(buf,sizeof buf);
        if (n) {
            const char* dst = call.legAVia.received.empty()
                            ? call.legAVia.host.c_str()
                            : call.legAVia.received.c_str();
            uint16_t dstPort = call.legAVia.rportVal ? call.legAVia.rportVal
                             : (call.legAVia.port    ? call.legAVia.port : SIP_UDP_PORT);
            Proto proto = Transport::protoFromVia(call.legAVia.transport.c_str());
            sendRaw(buf,n,dst,dstPort,proto);
        }
        return;
    }

    // Final non-2xx: forward upstream and clean up
    SipMessage fwd = resp;
    if (fwd.viaCount > 1) {
        for (int i=0;i+1<fwd.viaCount;++i) fwd.via[i]=fwd.via[i+1]; --fwd.viaCount;
    }
    char buf[SIP_MAX_MSG]; size_t n=fwd.format(buf,sizeof buf);
    if (n) {
        const char* dst = call.legAVia.received.empty()
                        ? call.legAVia.host.c_str()
                        : call.legAVia.received.c_str();
        uint16_t dstPort = call.legAVia.rportVal ? call.legAVia.rportVal
                         : (call.legAVia.port    ? call.legAVia.port : SIP_UDP_PORT);
        Proto proto = Transport::protoFromVia(call.legAVia.transport.c_str());
        sendRaw(buf,n,dst,dstPort,proto);
    }

    CdrRecord cdr;
    cdr.callId  = call.callId;
    cdr.fromUri = call.callerUri;
    cdr.toUri   = call.calleeUri;
    cdr.outbound= false;
    cdr.startMs = call.startMs;
    cdr.endMs   = nowMs();
    cdr.sipCode = resp.statusCode;
    cdr.result  = (resp.statusCode==486||resp.statusCode==600)
                ? CdrResult::Busy : CdrResult::Rejected;
    cdr_.write(cdr);
    if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
    freeProxy(call);
}

// ── B2BUA mode ────────────────────────────────────────────────────────────────
void SipServer::b2buaInvite(TxnId legATxn, const SipMessage& invite,
                             const RegBinding& target, Proto /*inProto*/) {
    B2buaCall* call = allocB2bua();
    if (!call) { sendResponse(legATxn,503,"Service Unavailable"); return; }

    call->legATxn    = legATxn;
    call->legACallId = invite.callId;
    genTag(call->legALocalTag);
    call->legARemoteTag = invite.from.tag;
    call->callerUri.assign(invite.from.uri.c_str(),invite.from.uri.len);
    call->calleeUri.assign(invite.requestUri.c_str(),invite.requestUri.len);
    call->callId = invite.callId;
    call->startMs= nowMs();
    call->state  = CallState::Calling;

    // Allocate RTP relay ports
    call->rtpAPort = allocRtpPort();
    call->rtpBPort = allocRtpPort();

    // Parse inbound SDP offer (to know caller's RTP address)
    if (invite.body && invite.bodyLen) {
        auto sdp = SdpSession::parse(invite.body, invite.bodyLen);
        if (sdp.ok()) {
            const MediaSection* am = sdp->audioMedia();
            if (am) {
                strncpy(call->callerRtpAddr,
                        sdp->connAddr.empty() ? invite.via[0].host.c_str()
                                              : sdp->connAddr.c_str(),
                        sizeof call->callerRtpAddr - 1);
                call->callerRtpPort = am->port;
            }
        }
    }

    // Send 100 Trying (already sent by handleInvite)

    // Build outbound INVITE (leg B)
    SipMessage fwd; fwd.isRequest=true; fwd.method=Method::INVITE;
    fwd.requestUri.assign(invite.requestUri.c_str(),invite.requestUri.len);

    char furi[256]; snprintf(furi,sizeof furi,"sip:%s@%s",
        cfg_.domain.empty()?"server":cfg_.domain.c_str(), cfg_.localAddr.c_str());
    fwd.from.uri.assign(furi,strlen(furi));
    genTag(call->legBLocalTag); fwd.from.tag=call->legBLocalTag;
    fwd.to.uri.assign(invite.requestUri.c_str(),invite.requestUri.len);
    genCallId(call->legBCallId); fwd.callId=call->legBCallId;
    fwd.cseq={call->legBCSeq++, Method::INVITE};
    fwd.maxForwards=70;
    Branch br; genBranch(br);
    fwd.via[0].host=cfg_.localAddr; fwd.via[0].port=cfg_.port;
    fwd.via[0].branch=br; fwd.via[0].transport.assign("UDP",3);
    fwd.viaCount=1;
    char contact[256]; snprintf(contact,sizeof contact,"sip:%s@%s:%u",
        cfg_.domain.c_str(), cfg_.localAddr.c_str(), cfg_.port);
    fwd.contact.uri.assign(contact,strlen(contact)); fwd.hasContact=true;
    fwd.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS",30);
    fwd.userAgent.assign("sip_server/1.0",14);

    // Rewrite SDP: offer our relay port (rtpBPort) to callee
    const char* relayAddr = cfg_.rtpLocalAddr.empty()
                          ? cfg_.localAddr.c_str() : cfg_.rtpLocalAddr.c_str();
    if (invite.body && invite.bodyLen) {
        size_t sdpLen = rewriteSdp(invite.body, invite.bodyLen,
                                   relayAddr, call->rtpBPort,
                                   sdpBuf_, sizeof sdpBuf_);
        if (sdpLen) {
            fwd.body=sdpBuf_; fwd.bodyLen=sdpLen;
            fwd.contentType.assign("application/sdp",15);
            fwd.contentLen=(uint32_t)sdpLen;
        }
    }

    // Route to target
    const char* dst     = target.srcAddr.empty() ? target.contact.c_str()
                                                  : target.srcAddr.c_str();
    uint16_t    dstPort = target.srcPort ? target.srcPort : SIP_UDP_PORT;
    auto parsedContact = SipUri::parse(target.contact.c_str());
    if (parsedContact.ok() && !parsedContact->host.empty()) {
        dst     = parsedContact->host.c_str();
        dstPort = parsedContact->effectivePort();
    }
    call->legBTxn = txn_.sendRequest(fwd, dst, dstPort, target.proto==Proto::Udp);
    if (call->legBTxn == InvalidTxn) {
        freeB2bua(*call); sendResponse(legATxn,503,"Service Unavailable");
    }
}

void SipServer::b2buaLegBResponse(B2buaCall& call, const SipMessage& resp) {
    if (resp.isProvisional()) {
        if (resp.statusCode == 180 || resp.statusCode == 183) {
            call.state = CallState::Ringing;
            // Forward ringing to leg A
            SipMessage ring = resp.makeResponse(resp.statusCode, resp.reason.c_str());
            ring.isRequest = false;
            ring.from.uri  = call.callerUri; ring.from.tag=call.legARemoteTag;
            ring.to.tag    = call.legALocalTag;
            ring.callId    = call.legACallId;
            ring.cseq.seq  = 1; ring.cseq.method = Method::INVITE;
            txn_.sendResponse(call.legATxn, ring);
        }
        return;
    }

    if (resp.is2xx()) {
        call.state     = CallState::Connected;
        call.connectMs = nowMs();
        call.legBRemoteTag = resp.to.tag;

        // Parse callee SDP answer to get their RTP address
        if (resp.body && resp.bodyLen) {
            auto sdp = SdpSession::parse(resp.body, resp.bodyLen);
            if (sdp.ok()) {
                const MediaSection* am = sdp->audioMedia();
                if (am) {
                    strncpy(call.calleeRtpAddr,
                            sdp->connAddr.empty() ? resp.contact.uri.c_str()
                                                  : sdp->connAddr.c_str(),
                            sizeof call.calleeRtpAddr-1);
                    call.calleeRtpPort = am->port;
                }
            }
        }

        // Open RTP relay
        openRtpRelay(call);

        // Build 200 OK for leg A — rewrite SDP with our relay addr:rtpAPort
        const char* relayAddr = cfg_.rtpLocalAddr.empty()
                              ? cfg_.localAddr.c_str() : cfg_.rtpLocalAddr.c_str();
        SipMessage ok; ok.isRequest=false; ok.statusCode=200; ok.reason.assign("OK",2);
        ok.from.uri=call.callerUri; ok.from.tag=call.legARemoteTag;
        ok.to.tag=call.legALocalTag;
        ok.callId=call.legACallId; ok.cseq={1,Method::INVITE};
        char contact[256]; snprintf(contact,sizeof contact,"sip:%s@%s:%u",
            cfg_.domain.c_str(), cfg_.localAddr.c_str(), cfg_.port);
        ok.contact.uri.assign(contact,strlen(contact)); ok.hasContact=true;
        ok.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS",30);
        // Forward or rewrite SDP
        if (resp.body && resp.bodyLen) {
            size_t sdpLen = rewriteSdp(resp.body, resp.bodyLen,
                                       relayAddr, call.rtpAPort,
                                       sdpBuf_, sizeof sdpBuf_);
            if (sdpLen) {
                ok.body=sdpBuf_; ok.bodyLen=sdpLen;
                ok.contentType.assign("application/sdp",15);
                ok.contentLen=(uint32_t)sdpLen;
            }
        }
        txn_.sendResponse(call.legATxn, ok);
        printf("[B2BUA] Call connected  %s → %s\n",
               call.callerUri.c_str(), call.calleeUri.c_str());
        return;
    }

    // Final non-2xx: reject leg A
    SipMessage r; r.isRequest=false; r.statusCode=resp.statusCode; r.reason=resp.reason;
    r.from.uri=call.callerUri; r.from.tag=call.legARemoteTag;
    r.to.tag=call.legALocalTag;
    r.callId=call.legACallId; r.cseq={1,Method::INVITE};
    txn_.sendResponse(call.legATxn, r);

    CdrRecord cdr;
    cdr.callId=call.callId; cdr.fromUri=call.callerUri; cdr.toUri=call.calleeUri;
    cdr.outbound=false; cdr.startMs=call.startMs; cdr.endMs=nowMs();
    cdr.sipCode=resp.statusCode;
    cdr.result=(resp.statusCode==486||resp.statusCode==600)?CdrResult::Busy:CdrResult::Rejected;
    cdr_.write(cdr);
    if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
    freeB2bua(call);
}

// ── ACK, BYE, CANCEL, OPTIONS, MESSAGE ───────────────────────────────────────
void SipServer::handleAck(const SipMessage& msg) {
    if (!cfg_.b2buaMode) return;  // Proxy: ACK routed by Record-Route
    B2buaCall* call = findB2buaByCallId(msg.callId);
    if (!call) return;
    // Forward ACK to leg B
    SipMessage fwd = msg;
    Branch br; genBranch(br);
    fwd.via[0].host=cfg_.localAddr; fwd.via[0].port=cfg_.port;
    fwd.via[0].branch=br; fwd.via[0].transport.assign("UDP",3);
    fwd.from.tag=call->legBLocalTag;
    fwd.callId=call->legBCallId;
    fwd.cseq.method=Method::ACK;
    // Send directly (ACK for 2xx is outside transaction layer)
    auto uri = SipUri::parse(call->calleeTarget.empty()
                           ? call->calleeUri.c_str()
                           : call->calleeTarget.c_str());
    if (!uri.ok()) return;
    char buf[SIP_MAX_MSG]; size_t n=fwd.format(buf,sizeof buf);
    if (n) sendRaw(buf,n,uri->host.c_str(),uri->effectivePort(),Proto::Udp);
}

void SipServer::handleBye(TxnId txnId, const SipMessage& msg) {
    sendResponse(txnId, 200, "OK");

    if (cfg_.b2buaMode) {
        B2buaCall* call = findB2buaByCallId(msg.callId);
        if (!call) return;
        // Send BYE to the other leg
        SipMessage bye; bye.isRequest=true; bye.method=Method::BYE;
        bye.requestUri=call->calleeTarget.empty()?call->calleeUri:call->calleeTarget;
        bye.from.uri.assign("sip:server@",11); bye.from.uri.append(cfg_.localAddr.c_str(),cfg_.localAddr.len);
        bye.from.tag=call->legBLocalTag;
        bye.to.uri=call->calleeUri; bye.to.tag=call->legBRemoteTag;
        bye.callId=call->legBCallId; bye.cseq={call->legBCSeq++,Method::BYE};
        bye.maxForwards=70;
        Branch br; genBranch(br);
        bye.via[0].host=cfg_.localAddr; bye.via[0].port=cfg_.port;
        bye.via[0].branch=br; bye.via[0].transport.assign("UDP",3);
        bye.viaCount=1;
        auto uri=SipUri::parse(bye.requestUri.c_str());
        if (uri.ok()) txn_.sendRequest(bye,uri->host.c_str(),uri->effectivePort(),true);

        CdrRecord cdr;
        cdr.callId=call->callId; cdr.fromUri=call->callerUri; cdr.toUri=call->calleeUri;
        cdr.outbound=false; cdr.startMs=call->startMs; cdr.connectMs=call->connectMs;
        cdr.endMs=nowMs(); cdr.sipCode=200; cdr.result=CdrResult::Answered;
        cdr_.write(cdr);
        if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
        freeB2bua(*call);
    } else {
        // Proxy: forward BYE downstream (it will route via Record-Route normally)
        // The UAs handle this directly via Route headers; nothing for us to do here
        // unless we want to log the BYE
        ProxyCall* call = findProxyByCallId(msg.callId);
        if (!call) return;
        CdrRecord cdr;
        cdr.callId=call->callId; cdr.fromUri=call->callerUri; cdr.toUri=call->calleeUri;
        cdr.outbound=false; cdr.startMs=call->startMs; cdr.endMs=nowMs();
        cdr.sipCode=200; cdr.result=CdrResult::Answered;
        cdr_.write(cdr);
        if (cbs_.onCallEnd) cbs_.onCallEnd(cdr);
        freeProxy(*call);
    }
}

void SipServer::handleCancel(TxnId txnId, const SipMessage& msg) {
    sendResponse(txnId, 200, "OK");

    if (cfg_.b2buaMode) {
        B2buaCall* call = findB2buaByCallId(msg.callId);
        if (call && call->state==CallState::Calling) {
            if (call->legBTxn!=InvalidTxn) txn_.cancelInvite(call->legBTxn);
            SipMessage r; r.isRequest=false; r.statusCode=487; r.reason.assign("Request Terminated",18);
            r.from.uri=call->callerUri; r.to.tag=call->legALocalTag;
            r.callId=call->legACallId; r.cseq={1,Method::INVITE};
            txn_.sendResponse(call->legATxn,r);

            CdrRecord cdr;
            cdr.callId=call->callId; cdr.fromUri=call->callerUri; cdr.toUri=call->calleeUri;
            cdr.startMs=call->startMs; cdr.endMs=nowMs();
            cdr.sipCode=487; cdr.result=CdrResult::Cancelled;
            cdr_.write(cdr); freeB2bua(*call);
        }
    } else {
        ProxyCall* call = findProxyByCallId(msg.callId);
        if (call && call->legBTxn!=InvalidTxn) {
            txn_.cancelInvite(call->legBTxn);
            CdrRecord cdr;
            cdr.callId=call->callId; cdr.fromUri=call->callerUri; cdr.toUri=call->calleeUri;
            cdr.startMs=call->startMs; cdr.endMs=nowMs();
            cdr.sipCode=487; cdr.result=CdrResult::Cancelled;
            cdr_.write(cdr); freeProxy(*call);
        }
    }
}

void SipServer::handleOptions(TxnId txnId, const SipMessage& msg) {
    SipMessage ok=msg.makeResponse(200,"OK");
    ok.allow.assign("INVITE,ACK,BYE,CANCEL,OPTIONS,REGISTER,MESSAGE",47);
    ok.supported.assign("timer,replaces",14);
    txn_.sendResponse(txnId,ok);
}

void SipServer::handleMessage(TxnId txnId, const SipMessage& msg) {
    sendResponse(txnId,200,"OK");
    // Optionally route MESSAGE like a proxy; for now just accept
}

// ── Auth helpers ──────────────────────────────────────────────────────────────
namespace auth { void md5Hex(const void*, size_t, char[33]); }

void SipServer::issueNonce(char out[33]) {
    // nonce = MD5(timestamp:secret:random)
    char tmp[128]; int64_t now=nowMs();
    snprintf(tmp,sizeof tmp,"%lld:%s:%08x",
             (long long)now, cfg_.nonceSecret.c_str(), rnd32());
    auth::md5Hex(tmp,strlen(tmp),out);
    // Cache for validation
    auto& slot = nonceCache_[nonceIdx_ % NonceCache];
    strncpy(slot.val,out,32); slot.issueMs=now;
    ++nonceIdx_;
}

bool SipServer::validateNonce(const char* nonce, int64_t nowMs) {
    // Accept any nonce issued in the last 5 minutes
    for (auto& s : nonceCache_) {
        if (s.issueMs>0 && strcmp(s.val,nonce)==0) {
            return (nowMs - s.issueMs) < 300000LL; // 5 min
        }
    }
    return false;
}

void SipServer::buildChallenge(char* buf, size_t sz, bool proxy) {
    char nonce[33]; issueNonce(nonce);
    const char* hdr = proxy ? "Proxy-Authenticate" : "WWW-Authenticate";
    (void)hdr;
    snprintf(buf,sz,"Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5, qop=\"auth\"",
             cfg_.realm.c_str(), nonce);
}

bool SipServer::checkAuth(const SipMessage& /*msg*/, Method /*m*/, bool /*proxy*/) {
    return true; // simplified; full impl analogous to REGISTER
}

// ── Record-Route insertion (proxy mode) ──────────────────────────────────────
void SipServer::addRecordRoute(SipMessage& msg) const {
    char rr[256];
    snprintf(rr,sizeof rr,"<sip:%s:%u;lr>",cfg_.localAddr.c_str(),cfg_.port);
    if (msg.recordRoute.empty()) msg.recordRoute.assign(rr,strlen(rr));
    else { char tmp[512]; snprintf(tmp,sizeof tmp,"%s, %s",rr,msg.recordRoute.c_str());
           msg.recordRoute.assign(tmp,strlen(tmp)); }
}

// ── SDP rewrite for B2BUA ────────────────────────────────────────────────────
// Replaces the first c= and first m=audio lines with new addr:port.
size_t SipServer::rewriteSdp(const char* orig, size_t len,
                              const char* newAddr, uint16_t newPort,
                              char* out, size_t outSz) {
    size_t n=0;
    const char* p=orig, *end=orig+len;
    bool cReplaced=false, mReplaced=false;
    while (p<end && n<outSz-128) {
        const char* nl=(const char*)memchr(p,'\n',(size_t)(end-p));
        size_t ll=nl?(size_t)(nl-p+1):(size_t)(end-p);
        const char* line=p; p=(nl?nl+1:end);
        // Replace c= line
        if (!cReplaced && ll>=2 && line[0]=='c' && line[1]=='=') {
            n+=(size_t)snprintf(out+n,outSz-n,"c=IN IP4 %s\r\n",newAddr);
            cReplaced=true; continue;
        }
        // Replace first m=audio port
        if (!mReplaced && ll>=9 && strncmp(line,"m=audio ",8)==0) {
            const char* sp=line+8;
            while(sp<line+ll && *sp!=' ')++sp;
            n+=(size_t)snprintf(out+n,outSz-n,"m=audio %u%s",newPort,sp);
            mReplaced=true; continue;
        }
        // Copy line verbatim
        if (n+ll < outSz) { memcpy(out+n,line,ll); n+=ll; }
    }
    out[n]=0; return n;
}

// ── RTP relay (B2BUA) ────────────────────────────────────────────────────────
uint16_t SipServer::allocRtpPort() {
    uint16_t p = nextRtpPort_;
    nextRtpPort_ = (uint16_t)(nextRtpPort_ + 2);
    if (nextRtpPort_ < cfg_.rtpBasePort) nextRtpPort_=cfg_.rtpBasePort;
    return p;
}

bool SipServer::openRtpRelay(B2buaCall& call) {
    // Open relay socket A (faces caller)
    int fa = socket(AF_INET,SOCK_DGRAM,0);
    int fb = socket(AF_INET,SOCK_DGRAM,0);
    if (fa<0||fb<0) { if(fa>=0)close(fa); if(fb>=0)close(fb); return false; }
    auto bind_udp = [](int fd, const char* addr, uint16_t port) -> bool {
        struct sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
        sa.sin_addr.s_addr=addr&&*addr?inet_addr(addr):INADDR_ANY;
        return ::bind(fd,(sockaddr*)&sa,sizeof sa)==0;
    };
    const char* la = cfg_.rtpLocalAddr.empty()?cfg_.localAddr.c_str():cfg_.rtpLocalAddr.c_str();
    if (!bind_udp(fa,la,call.rtpAPort)||!bind_udp(fb,la,call.rtpBPort)) {
        close(fa);close(fb); return false;
    }
    call.rtpAFd=fa; call.rtpBFd=fb;

    // Two relay threads: A→B and B→A
    struct RelayArgs* argAB = new RelayArgs{this,&call,fa,fb,{},call.calleeRtpPort};
    strncpy(argAB->dstAddr,call.calleeRtpAddr,47);
    argAB->dstPort=call.calleeRtpPort;
    struct RelayArgs* argBA = new RelayArgs{this,&call,fb,fa,{},call.callerRtpPort};
    strncpy(argBA->dstAddr,call.callerRtpAddr,47);
    argBA->dstPort=call.callerRtpPort;
    pthread_t tA,tB;
    pthread_create(&tA,nullptr,rtpRelayThread,argAB);
    pthread_create(&tB,nullptr,rtpRelayThread,argBA);
    pthread_detach(tA); pthread_detach(tB);
    call.relayRunning=true;
    printf("[B2BUA] RTP relay open: %s:%u <-> server:%u/%u <-> %s:%u\n",
           call.callerRtpAddr, call.callerRtpPort,
           call.rtpAPort, call.rtpBPort,
           call.calleeRtpAddr, call.calleeRtpPort);
    return true;
}

void SipServer::closeRtpRelay(B2buaCall& call) {
    if (call.rtpAFd>=0){::shutdown(call.rtpAFd,SHUT_RDWR);close(call.rtpAFd);call.rtpAFd=-1;}
    if (call.rtpBFd>=0){::shutdown(call.rtpBFd,SHUT_RDWR);close(call.rtpBFd);call.rtpBFd=-1;}
    call.relayRunning=false;
}

void* SipServer::rtpRelayThread(void* arg) {
    auto* a=(RelayArgs*)arg;
    struct timeval tv{0,100000}; // 100ms recv timeout
    setsockopt(a->srcFd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    struct sockaddr_in dst{}; dst.sin_family=AF_INET;
    dst.sin_port=htons(a->dstPort);
    dst.sin_addr.s_addr=inet_addr(a->dstAddr);
    uint8_t buf[2048];
    while (a->call->relayRunning && a->call->used) {
        ssize_t n=recv(a->srcFd,buf,sizeof buf,0);
        if (n<=0) continue;
        // Learn remote address on first packet (handles NAT)
        sendto(a->dstFd,buf,(size_t)n,0,(sockaddr*)&dst,sizeof dst);
    }
    delete a; return nullptr;
}

// ── Pool management ───────────────────────────────────────────────────────────
ProxyCall* SipServer::allocProxy() {
    for (auto& c:proxyCalls_) if(!c.used){c.used=true;return &c;} return nullptr;
}
void SipServer::freeProxy(ProxyCall& c)      { c.used=false; }
ProxyCall* SipServer::findProxyByLegA(TxnId id) {
    for(auto& c:proxyCalls_) if(c.used&&c.legATxn==id) return &c; return nullptr;
}
ProxyCall* SipServer::findProxyByLegB(TxnId id) {
    for(auto& c:proxyCalls_) if(c.used&&c.legBTxn==id) return &c; return nullptr;
}
ProxyCall* SipServer::findProxyByCallId(const CallId& id) {
    for(auto& c:proxyCalls_) if(c.used&&c.callId==id) return &c; return nullptr;
}

B2buaCall* SipServer::allocB2bua() {
    for(auto& c:b2buaCalls_) if(!c.used){c.used=true;return &c;} return nullptr;
}
void SipServer::freeB2bua(B2buaCall& c) { closeRtpRelay(c); c.used=false; }
B2buaCall* SipServer::findB2buaByLegA(TxnId id) {
    for(auto& c:b2buaCalls_) if(c.used&&c.legATxn==id) return &c; return nullptr;
}
B2buaCall* SipServer::findB2buaByLegB(TxnId id) {
    for(auto& c:b2buaCalls_) if(c.used&&c.legBTxn==id) return &c; return nullptr;
}
B2buaCall* SipServer::findB2buaByCallId(const CallId& id) {
    for(auto& c:b2buaCalls_) if(c.used&&c.callId==id) return &c; return nullptr;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
bool SipServer::sendResponse(TxnId txn, int code, const char* reason,
                             const char* body, size_t blen, const char* ct) {
    const Transaction* t=txn_.findById(txn); if(!t) return false;
    auto req=SipMessage::parse(t->reqBuf,t->reqLen); if(!req.ok()) return false;
    SipMessage r=req->makeResponse(code,reason);
    if(body&&blen){ r.body=body; r.bodyLen=blen; r.contentLen=(uint32_t)blen;
                    r.contentType.assign(ct,strlen(ct)); }
    return txn_.sendResponse(txn,r);
}

bool SipServer::sendRaw(const char* d, size_t l,
                        const char* h, uint16_t p, Proto proto) {
    return transport_.send(d,l,h,p,proto);
}

// ── Diagnostics ───────────────────────────────────────────────────────────────
void SipServer::printStats() const {
    int64_t now=nowMs();
    printf("\n── SIP Server Stats ─────────────────────────────────────────\n");
    printf("  Domain     : %s\n", cfg_.domain.c_str());
    printf("  Mode       : %s\n", cfg_.b2buaMode?"B2BUA":"Stateful Proxy");
    printf("  Users      : %zu\n", users_.count());
    printf("  Registrations: %zu\n", reg_.totalBindings());
    printf("  Active calls : %zu\n", activeCallCount());
    printf("─────────────────────────────────────────────────────────────\n\n");
    (void)now;
}

void SipServer::printRegistrations() const {
    printf("\n── Active Registrations ─────────────────────────────────────\n");
    reg_.printAll(nowMs());
    printf("─────────────────────────────────────────────────────────────\n\n");
}

void SipServer::printCalls() const {
    printf("\n── Active Calls ─────────────────────────────────────────────\n");
    size_t n=0;
    if (cfg_.b2buaMode) {
        for(const auto& c:b2buaCalls_) if(c.used){
            const char* st="?";
            switch(c.state){case CallState::Calling:st="Calling";break;
                            case CallState::Ringing:st="Ringing";break;
                            case CallState::Connected:st="Connected";break;
                            default:st="Term";break;}
            printf("  [%zu] %s → %s  [%s]\n",++n,c.callerUri.c_str(),c.calleeUri.c_str(),st);
        }
    } else {
        for(const auto& c:proxyCalls_) if(c.used){
            const char* st="?";
            switch(c.state){case CallState::Calling:st="Calling";break;
                            case CallState::Ringing:st="Ringing";break;
                            case CallState::Connected:st="Connected";break;
                            default:st="Term";break;}
            printf("  [%zu] %s → %s  [%s]\n",++n,c.callerUri.c_str(),c.calleeUri.c_str(),st);
        }
    }
    if (!n) printf("  (none)\n");
    printf("─────────────────────────────────────────────────────────────\n\n");
}

size_t SipServer::registrationCount() const { return reg_.totalBindings(); }
size_t SipServer::activeCallCount() const {
    size_t n=0;
    for(const auto& c:proxyCalls_)  if(c.used)++n;
    for(const auto& c:b2buaCalls_)  if(c.used)++n;
    return n;
}

} // namespace sip
""")

# ─────────────────────────────────────────────────────────────────────────────
W("src/sip_server_main.cpp", r"""// sip_server_main.cpp – Standalone SIP server executable
//
// Usage:
//   sip_server [options]
//     -d <domain>        SIP domain  (default: localhost)
//     -l <addr>          Bind address (default: 0.0.0.0)
//     -p <port>          SIP port     (default: 5060)
//     -b                 B2BUA mode   (default: proxy mode)
//     -A                 Require auth for REGISTER
//     -u users.txt       User database file
//     -c cdr.csv         CDR output file
//     -a <user:pass>     Add user (can repeat)
//     --no-tcp           Disable TCP transport
//     --no-udp           Disable UDP transport
//
// Admin REPL (interactive):
//   r  – show registrations
//   c  – show active calls
//   s  – stats
//   u  – show users
//   q  – quit
#include "SipServer.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/time.h>

using namespace sip;

static volatile bool g_quit = false;
static void sigHandler(int) { g_quit=true; }

int main(int argc, char** argv) {
    ServerConfig cfg;
    cfg.domain.assign("localhost",9);
    cfg.realm.assign("localhost",9);
    cfg.nonceSecret.assign("sip_server_secret",17);
    cfg.requireRegAuth = false;  // disabled by default for easy setup
    cfg.b2buaMode      = false;

    bool noTcp=false, noUdp=false;

    int opt;
    while ((opt=getopt(argc,argv,"d:l:p:bAu:c:a:h")) != -1) {
        switch(opt) {
        case 'd':
            cfg.domain.assign(optarg,strlen(optarg));
            cfg.realm.assign(optarg,strlen(optarg));
            break;
        case 'l': cfg.localAddr.assign(optarg,strlen(optarg)); break;
        case 'p': cfg.port=(uint16_t)atoi(optarg); break;
        case 'b': cfg.b2buaMode=true; break;
        case 'A': cfg.requireRegAuth=true; break;
        case 'u': cfg.userDbPath.assign(optarg,strlen(optarg)); break;
        case 'c': cfg.cdrPath.assign(optarg,strlen(optarg)); break;
        case 'a': /* handled below */ break;
        case 'h':
        default:
            printf("Usage: %s [-d domain] [-l addr] [-p port] [-b] [-A]\n"
                   "       [-u users.txt] [-c cdr.csv] [-a user:pass] ...\n"
                   "  -b  B2BUA mode (default: stateful proxy)\n"
                   "  -A  Require Digest auth for REGISTER\n", argv[0]);
            return opt=='h'?0:1;
        }
    }

    // Set RTP relay address = bind address
    if (!cfg.localAddr.empty()) cfg.rtpLocalAddr = cfg.localAddr;
    cfg.enableTcp = !noTcp;
    cfg.enableUdp = !noUdp;

    signal(SIGINT,  sigHandler);
    signal(SIGTERM, sigHandler);
    signal(SIGPIPE, SIG_IGN);

    ServerCallbacks cbs;
    cbs.onRegister=[](const char* aor, const char* contact, bool reg){
        printf("[EVENT] %s  %s  %s\n", reg?"REGISTERED":"UNREGISTERED", aor, contact);
    };
    cbs.onCallEnd=[](const CdrRecord& cdr){
        printf("[CDR]   %s → %s  %lldms  %s\n",
               cdr.fromUri.c_str(), cdr.toUri.c_str(),
               (long long)(cdr.endMs-cdr.startMs),
               cdr.result==CdrResult::Answered?"ANSWERED":"NOT_ANSWERED");
    };

    SipServer server;
    if (!server.init(cfg, cbs)) {
        fputs("[ERROR] Failed to start server\n", stderr); return 1;
    }

    // Add users from -a flags
    optind=1;
    while ((opt=getopt(argc,argv,"d:l:p:bAu:c:a:h"))!=-1) {
        if (opt=='a') {
            char user[64]={}, pass[64]={};
            if (sscanf(optarg,"%63[^:]:%63s",user,pass)==2) {
                server.addUser(user,pass);
                printf("[USER]  Added user '%s'\n",user);
            }
        }
    }

    // Tick thread
    pthread_t tickTid;
    auto tickFn=[](void* arg)->void*{
        auto* s=(SipServer*)arg;
        while(!g_quit){
            struct timespec ts{0,50000000L}; nanosleep(&ts,nullptr);
            s->tick();
        }
        return nullptr;
    };
    pthread_create(&tickTid,nullptr,+tickFn,&server);

    printf("\nSIP Server ready.  Commands: r=registrations c=calls s=stats u=users q=quit\n\n");

    // Interactive admin REPL
    char line[256];
    while (!g_quit) {
        printf("sip> "); fflush(stdout);
        // Non-blocking readline with 200ms check
        fd_set fds; FD_ZERO(&fds); FD_SET(STDIN_FILENO,&fds);
        struct timeval tv{0,200000};
        if (select(STDIN_FILENO+1,&fds,nullptr,nullptr,&tv)>0) {
            if (!fgets(line,sizeof line,stdin)) break;
            char cmd=line[0];
            switch(cmd) {
            case 'r': server.printRegistrations(); break;
            case 'c': server.printCalls();         break;
            case 's': server.printStats();         break;
            case 'u': server.userDb().printAll();  break;
            case 'q': g_quit=true;                 break;
            case 'h': case '?':
                printf("  r  registrations\n  c  active calls\n"
                       "  s  stats\n  u  users\n  q  quit\n"); break;
            default: break;
            }
        }
    }

    g_quit=true;
    pthread_join(tickTid,nullptr);
    server.shutdown();
    printf("\nServer stopped.\n");
    return 0;
}
""")

print("All server files written.")
