// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file SipStack.h
 * @brief SIP user-agent stack and lightweight registrar server API.
 *
 * SIP transport supports UDP/TCP via Transport (RFC 3261 section 18).
 * RTP media transport uses UDP (RFC 3550).
 */
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

/**
 * @brief Runtime configuration for SipStack.
 */
struct StackConfig {
    /** Local SIP username for AOR/contact generation. */
    Str<64>  localUser;           // SIP AOR username
    /** Local SIP domain/realm. */
    Str<64>  localDomain;         // SIP domain / realm
    /** Local bind address for SIP sockets. */
    Str<64>  localAddr;           // IP to bind (empty = INADDR_ANY)
    /** SIP listen port shared by UDP and TCP listeners. */
    uint16_t localPort    = SIP_UDP_PORT;  // shared by UDP and TCP

    // Transport flags
    /** Enable UDP transport. */
    bool     enableUdp    = true;  // listen/send on UDP
    /** Enable TCP transport. */
    bool     enableTcp    = true;  // listen/accept on TCP, connect outbound

    // Preferred outbound transport for new requests.
    // "UDP" (default) or "TCP".  Individual calls can override per-dialog
    // by inspecting the remote Contact/Record-Route.
    /** Preferred outbound transport for new requests. */
    Proto    outboundProto = Proto::Udp;

    // Outbound registrar (UAC mode)
    /** Registrar host in UAC registration mode. */
    Str<64>  registrarHost;
    /** Registrar port in UAC registration mode. */
    uint16_t registrarPort  = SIP_UDP_PORT;
    /** Transport used to reach registrar. */
    Proto    registrarProto = Proto::Udp;  // transport to reach registrar

    // Credentials
    /** Digest auth username. */
    Str<64>  authUser;
    /** Digest auth password. */
    Str<64>  authPass;
    /** Optional pinned auth realm (empty accepts any). */
    Str<64>  authRealm;   // empty -> accept any realm

    // Operational flags
    /** Enable user-agent client behavior. */
    bool     uac          = true;
    /** Enable user-agent server behavior. */
    bool     uas          = true;
    /** Enable proxy-like request handling path. */
    bool     proxyMode    = false;
    /** Enable embedded registrar service mode. */
    bool     registrarSv  = false;

    /** REGISTER expiration seconds. */
    uint32_t regExpires   = 3600;
    /** Base local RTP port allocation start. */
    uint16_t rtpBasePort  = SIP_RTP_BASE_PORT;
    /** RTP address advertised in SDP c= lines. */
    Str<64>  rtpLocalAddr;   // IP for SDP c=; defaults to localAddr
};

/** @brief Public dialog/call handle type used by SipStack API. */
using CallHandle = DialogId;

/**
 * @brief Application callbacks raised by SipStack.
 */
struct StackCallbacks {
    /** Incoming INVITE callback. */
    std::function<void(CallHandle, const SipMessage&)> onInvite;
    /** Dialog connected callback with associated RTP session. */
    std::function<void(CallHandle, RtpSession*)>       onConnected;
    /** Dialog termination callback with SIP code. */
    std::function<void(CallHandle, int code)>          onBye;
    /** Incoming MESSAGE callback. */
    std::function<void(const char* from,
                       const char* body, size_t bodyLen,
                       const char* ct)>                onMessage;
    /** REGISTER result callback. */
    std::function<void(bool ok, int code)>             onRegistered;
    /** OPTIONS result callback. */
    std::function<void(bool ok, int code)>             onOptions;
    /** Raw unmatched request callback. */
    std::function<void(const SipMessage&, TxnId)>      onRequest;
};

/**
 * @brief Registrar binding entry used when registrarSv mode is enabled.
 */
struct RegBinding {
    /** Address-of-record URI (example: sip:user at domain). */
    URI      aor;
    /** Registered contact URI. */
    URI      contact;
    /** Source IP address of binding. */
    Str<48>  srcAddr;
    /** Source SIP port of binding. */
    uint16_t srcPort   = 0;
    /** Transport used by binding. */
    Proto    proto     = Proto::Udp;
    /** Absolute expiry timestamp in milliseconds. */
    int64_t  expiresAt = 0;
    /** Internal slot occupancy marker. */
    bool     used      = false;
};

/**
 * @brief Main SIP stack API for client and embedded server flows.
 */
class SipStack {
public:
    /**
     * @brief Initialize stack transport, transaction/dialog layers, and codecs.
     * @param cfg Stack configuration.
     * @param cbs Application callbacks.
     * @param codecs Codec registry used for SDP negotiation and RTP sessions.
     * @return true on success.
     */
    bool init(StackConfig cfg, StackCallbacks cbs, CodecRegistry* codecs);

    /** @brief Shutdown stack and release sockets/media sessions. */
    void shutdown();

    // ── UAC ──────────────────────────────────────────────────────────────────
    /**
     * @brief Send REGISTER to registrarHost.
     * @param expiresSec Requested expiration (0 uses cfg.regExpires).
     * @return true if REGISTER transaction is created.
     */
    bool       doRegister(uint32_t expiresSec = 0);

    /**
     * @brief Place an outbound INVITE call.
    * @param target Target URI or user\@host.
     * @param proto Outbound transport.
     * @return Dialog handle or InvalidDialog on failure.
     */
    CallHandle call(const char* target, Proto proto = Proto::Udp);

    /** @brief Accept an incoming INVITE dialog. */
    bool       accept(CallHandle h);

    /** @brief Reject an incoming INVITE dialog. */
    bool       reject(CallHandle h, int code = 486,
                      const char* reason = "Busy Here");

    /** @brief Send BYE for a confirmed dialog. */
    bool       bye(CallHandle h);

    /** @brief Send CANCEL for an early outbound INVITE. */
    bool       cancel(CallHandle h);

    /** @brief Send hold re-INVITE. */
    bool       hold(CallHandle h);

    /** @brief Send resume re-INVITE. */
    bool       resume(CallHandle h);

    /** @brief Send RFC4733 DTMF event on an active RTP session. */
    bool       sendDtmf(CallHandle h, uint8_t digit);

    /** @brief Send SIP MESSAGE to a target URI. */
    bool       sendMessage(const char* target, const char* body, size_t len,
                           const char* ct = "text/plain",
                           Proto proto = Proto::Udp);

    /** @brief Send SIP OPTIONS to a target URI. */
    bool       options(const char* target, Proto proto = Proto::Udp);

    // ── Server ───────────────────────────────────────────────────────────────
    /**
     * @brief Build and send a response for an existing server transaction.
     */
    bool sendResponse(TxnId txn, int code, const char* reason,
                      const char* body = nullptr, size_t bodyLen = 0,
                      const char* ct   = nullptr);

    /** @brief Look up active registrar binding by AOR in registrarSv mode. */
    const RegBinding* lookupAOR(const char* aor) const;

    // ── RTP accessors ─────────────────────────────────────────────────────────
    /** @brief Return RTP session associated with a dialog, if any. */
    RtpSession* rtpOf(CallHandle h);

    // ── Maintenance ───────────────────────────────────────────────────────────
    /** @brief Progress timers and transaction state machines. */
    void tick();

    /** @brief Return active immutable stack configuration. */
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
    void handleInviteResp     (Dialog*, const SipMessage&);
    void handleRegisterResp   (const SipMessage&);
    void retryInviteWithAuth  (Dialog*, const SipMessage& challenge);

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
