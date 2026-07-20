#!/usr/bin/env python3
# Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
# All rights reserved.

"""Rewrite SipStack.h with dual-transport (UDP+TCP) support."""
import os

path = "/home/mkwiatkowski/Projects/SIP/include/SipStack.h"

content = r"""// SipStack.h – Full SIP User Agent + Server core (RFC 3261)
// Transport: UDP + TCP via Transport class (RFC 3261 §18)
// RTP:       always UDP (RFC 3550)
#pragma once
#include "SipMessage.h"
#include "Transaction.h"
#include "Dialog.h"
#include "Sdp.h"
#include "Rtp.h"
#include "Codec.h"
#include "Transport.h"
#include <functional>
#include <pthread.h>

namespace sip {

// ── Configuration ─────────────────────────────────────────────────────────────
struct StackConfig {
    Str<64>  localUser;           // SIP AOR username
    Str<64>  localDomain;         // SIP domain / realm
    Str<64>  localAddr;           // IP to bind (empty = INADDR_ANY)
    uint16_t localPort    = SIP_UDP_PORT;  // shared by UDP and TCP

    // Transport flags
    bool     enableUdp    = true;  // listen/send on UDP
    bool     enableTcp    = true;  // listen/accept on TCP, connect outbound

    // Preferred outbound transport for new requests.
    // "UDP" (default) or "TCP".  Individual calls can override per-dialog
    // by inspecting the remote Contact/Record-Route.
    Proto    outboundProto = Proto::Udp;

    // Outbound registrar (UAC mode)
    Str<64>  registrarHost;
    uint16_t registrarPort  = SIP_UDP_PORT;
    Proto    registrarProto = Proto::Udp;  // transport to reach registrar

    // Credentials
    Str<64>  authUser;
    Str<64>  authPass;
    Str<64>  authRealm;   // empty -> accept any realm

    // Operational flags
    bool     uac          = true;
    bool     uas          = true;
    bool     proxyMode    = false;
    bool     registrarSv  = false;

    uint32_t regExpires   = 3600;
    uint16_t rtpBasePort  = SIP_RTP_BASE_PORT;
    Str<64>  rtpLocalAddr;   // IP for SDP c=; defaults to localAddr
};

using CallHandle = DialogId;

// ── Application callbacks ─────────────────────────────────────────────────────
struct StackCallbacks {
    std::function<void(CallHandle, const SipMessage&)> onInvite;
    std::function<void(CallHandle, RtpSession*)>       onConnected;
    std::function<void(CallHandle, int code)>          onBye;
    std::function<void(const char* from,
                       const char* body, size_t bodyLen,
                       const char* ct)>                onMessage;
    std::function<void(bool ok, int code)>             onRegistered;
    std::function<void(bool ok, int code)>             onOptions;
    std::function<void(const SipMessage&, TxnId)>      onRequest;
};

// ── Registrar binding (server mode) ──────────────────────────────────────────
struct RegBinding {
    URI      aor;
    URI      contact;
    Str<48>  srcAddr;
    uint16_t srcPort   = 0;
    Proto    proto     = Proto::Udp;
    int64_t  expiresAt = 0;
    bool     used      = false;
};

// ── Main stack ────────────────────────────────────────────────────────────────
class SipStack {
public:
    bool init(StackConfig cfg, StackCallbacks cbs, CodecRegistry* codecs);
    void shutdown();

    // ── UAC ──────────────────────────────────────────────────────────────────
    bool       doRegister(uint32_t expiresSec = 0);
    CallHandle call(const char* target, Proto proto = Proto::Udp);
    bool       accept(CallHandle h);
    bool       reject(CallHandle h, int code = 486,
                      const char* reason = "Busy Here");
    bool       bye(CallHandle h);
    bool       cancel(CallHandle h);
    bool       hold(CallHandle h);
    bool       resume(CallHandle h);
    bool       sendDtmf(CallHandle h, uint8_t digit);
    bool       sendMessage(const char* target, const char* body, size_t len,
                           const char* ct = "text/plain",
                           Proto proto = Proto::Udp);
    bool       options(const char* target, Proto proto = Proto::Udp);

    // ── Server ───────────────────────────────────────────────────────────────
    bool sendResponse(TxnId txn, int code, const char* reason,
                      const char* body = nullptr, size_t bodyLen = 0,
                      const char* ct   = nullptr);
    const RegBinding* lookupAOR(const char* aor) const;

    // ── RTP accessors ─────────────────────────────────────────────────────────
    RtpSession* rtpOf(CallHandle h);

    // ── Maintenance ───────────────────────────────────────────────────────────
    void tick();

    const StackConfig& config() const { return cfg_; }

private:
    StackConfig    cfg_;
    StackCallbacks cbs_;
    CodecRegistry* codecs_ = nullptr;

    // Dual-transport layer (UDP + TCP)
    Transport  transport_;

    TransactionLayer txn_;
    DialogLayer      dlg_;

    // REGISTER state machine
    uint32_t   regCSeq_    = 0;
    CallId     regCallId_;
    TxnId      regTxn_     = InvalidTxn;
    bool       registered_ = false;
    int64_t    regRetry_   = 0;
    auth::Challenge regChallenge_;
    bool       regNeedAuth_= false;
    uint32_t   regAuthNc_  = 0;

    // Per-dialog RTP pool
    struct RtpSlot { DialogId dlgId=0; RtpSession sess; bool used=false; };
    static constexpr size_t RtpSlots = SIP_MAX_DIALOGS;
    RtpSlot    rtpPool_[RtpSlots];
    uint16_t   nextRtpPort_ = SIP_RTP_BASE_PORT;

    // Registrar bindings pool
    RegBinding bindings_[SIP_MAX_REGS];

    // Scratch buffers (protected by mu_)
    char       txBuf_[SIP_MAX_MSG];
    char       sdpBuf_[1600];

    pthread_mutex_t mu_ = PTHREAD_MUTEX_INITIALIZER;
    struct Guard { pthread_mutex_t& m;
        Guard(pthread_mutex_t& m):m(m){pthread_mutex_lock(&m);}
        ~Guard(){pthread_mutex_unlock(&m);}
    };

    // ── Internal ─────────────────────────────────────────────────────────────
    // Called by Transport for every received message (UDP or TCP)
    void onRecv(const char* buf, size_t len,
                const char* host, uint16_t port, bool isTcp);

    // Transaction callbacks
    void onTxnResponse  (TxnId, const SipMessage&);
    void onTxnRequest   (TxnId, const SipMessage&);
    void onTxnTerminated(TxnId);

    // Request handlers (UAS)
    void handleInvite  (TxnId, const SipMessage&, const char* host,
                        uint16_t port, Proto proto);
    void handleAck     (const SipMessage&);
    void handleBye     (TxnId, const SipMessage&);
    void handleCancel  (TxnId, const SipMessage&);
    void handleRegister(TxnId, const SipMessage&, Proto proto);
    void handleMessage (TxnId, const SipMessage&);
    void handleOptions (TxnId, const SipMessage&);
    void handleUpdate  (TxnId, const SipMessage&);

    // Response handlers (UAC)
    void handleInviteResp  (Dialog*, const SipMessage&);
    void handleRegisterResp(const SipMessage&);

    // RTP helpers
    RtpSession* rtpAlloc(DialogId id);
    void        rtpFree (DialogId id);
    uint16_t    rtpNextPort();

    // Build a Via header for an outgoing request
    void fillVia(SipMessage& msg, Proto proto) const;

    // Identifier generators (RFC 3261 §8.1.1)
    void genBranch(Branch& b) const;
    void genCallId(CallId& id) const;
    void genTag   (Tag& t) const;

    // SDP helpers
    size_t makeSdpOffer (char* buf, size_t sz, uint16_t rtpPort) const;
    size_t makeSdpAnswer(char* buf, size_t sz, const SdpSession& offer,
                         uint16_t rtpPort) const;

    // Transport send
    bool sendMsg(const SipMessage& msg, const char* host, uint16_t port,
                 Proto proto);
    bool sendRaw(const char* data, size_t len,
                 const char* host, uint16_t port, Proto proto);

    static int64_t nowMs();
};

} // namespace sip
"""

with open(path, "w") as f:
    f.write(content)
print(f"Written {len(content)} bytes to {path}")
