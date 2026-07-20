// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file Dialog.h
 * @brief SIP dialog state model and lookup/update helpers.
 */
#pragma once
#include "SipMessage.h"
#include "Transaction.h"
#include "Transport.h"

namespace sip {

/** @brief Opaque dialog identifier type. */
using DialogId = uint32_t;
/** @brief Invalid dialog id sentinel. */
constexpr DialogId InvalidDialog = 0;

/** @brief RFC3261 dialog state. */
enum class DialogState : uint8_t {
    Null,       // before first provisional
    Early,      // 1xx with To-tag received/sent
    Confirmed,  // 2xx received/sent
    Terminated,
};

/** @brief Dialog record for one SIP call leg relationship. */
struct Dialog {
    /** Dialog identifier. */
    DialogId    id          = 0;
    /** Current dialog state. */
    DialogState state       = DialogState::Null;

    /** Call-ID shared by both peers. */
    CallId   callId;
    /** Local tag value. */
    Tag      localTag;
    /** Remote tag value. */
    Tag      remoteTag;

    /** Local next/last CSeq. */
    uint32_t localCSeq  = 0;
    /** Highest remote CSeq seen. */
    uint32_t remoteCSeq = 0;
    /** Local URI (typically From URI). */
    URI      localUri;         // From URI
    /** Remote URI (typically To URI). */
    URI      remoteUri;        // To URI
    /** Remote target URI (Contact). */
    URI      remoteTarget;     // Contact of remote party

    /** Route set learned for in-dialog requests. */
    RouteSet routeSet;
    /** True if local side initiated the dialog (UAC). */
    bool     isUAC  = true;   // did we initiate?
    /** Transport protocol used to establish dialog. */
    Proto    proto  = Proto::Udp; // transport used to establish dialog

    // Associated transaction IDs
    /** Initial INVITE transaction id. */
    TxnId    inviteTxn  = InvalidTxn;
    /** Most recent in-dialog transaction id. */
    TxnId    currentTxn = InvalidTxn;

    // Negotiated RTP parameters (filled after SDP answer)
    /** Remote RTP host/address. */
    Str<64>  remoteRtpHost;
    /** Remote RTP UDP port. */
    uint16_t remoteRtpPort  = 0;
    /** Negotiated RTP payload type. */
    uint8_t  negotiatedPT   = 0;

    // Per-dialog INVITE auth retry (RFC 3261 §22.2)
    /** Last digest challenge for INVITE retry. */
    auth::Challenge inviteChallenge;
    /** True if invite retry must include auth header. */
    bool     inviteNeedAuth = false;
    /** Digest nonce-count for INVITE retries. */
    uint32_t inviteAuthNc   = 0;
    /** Locally reserved RTP port for current invite leg. */
    uint16_t inviteRtpPort  = 0;   // RTP port reserved for this call
    /** Original INVITE target URI for retry/re-INVITE. */
    URI      inviteTarget;         // original target URI for re-INVITE
    /** Transport for invite target path. */
    Proto    inviteProto    = Proto::Udp;

    /** @brief Increment and return next outgoing CSeq. */
    uint32_t nextCSeq() { return ++localCSeq; }

    /** @brief Match incoming message to this dialog identity. */
    bool matches(const SipMessage& msg) const;
};

/** @brief Dialog pool and state update helpers. */
class DialogLayer {
public:
    /** @brief Create UAC dialog on outgoing INVITE. */
    Dialog* createUAC(const SipMessage& inviteReq, const Tag& localTag);
    /** @brief Create UAS dialog on incoming INVITE. */
    Dialog* createUAS(const SipMessage& inviteReq, const Tag& localTag);

    /**
     * @brief Update dialog state from SIP message event.
        * @param d Dialog to update.
        * @param msg SIP request/response event.
     * @param isLocal True when message originated locally; false when received.
     */
    void update(Dialog& d, const SipMessage& msg, bool isLocal);

    /** @brief Find dialog matching incoming message tuple. */
    Dialog* find(const SipMessage& msg);
    /** @brief Find dialog by id. */
    Dialog* findById(DialogId id);

    /** @brief Mark dialog terminated and free from pool. */
    void terminate(Dialog& d);

    /** @brief Iterate dialogs in internal pool. */
    template<class F> void forEach(F fn) { pool_.forEach(fn); }
    /** @brief Number of active dialogs. */
    size_t count() const { return pool_.count(); }

private:
    Pool<Dialog, SIP_MAX_DIALOGS> pool_;
    uint32_t nextId_ = 1;
};

} // namespace sip
