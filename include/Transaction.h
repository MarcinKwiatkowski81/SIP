// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file Transaction.h
 * @brief SIP transaction layer API (RFC3261 section 17).
 */
#pragma once
#include "SipMessage.h"
#include <functional>

namespace sip {

/** @brief Opaque transaction id type. */
using TxnId = uint32_t;
/** @brief Invalid transaction id sentinel. */
constexpr TxnId InvalidTxn = 0;

/** @brief Transaction finite-state machine states. */
enum class TxnState : uint8_t {
    // INVITE Client Transaction (ICT)
    ICT_Calling, ICT_Proceeding, ICT_Completed, ICT_Terminated,
    // Non-INVITE Client Transaction (NICT)
    NICT_Trying, NICT_Proceeding, NICT_Completed, NICT_Terminated,
    // INVITE Server Transaction (IST)
    IST_Proceeding, IST_Completed, IST_Confirmed, IST_Terminated,
    // Non-INVITE Server Transaction (NIST)
    NIST_Trying, NIST_Proceeding, NIST_Completed, NIST_Terminated,
};

/** @brief Transaction role in FSM (client or server). */
enum class TxnRole : uint8_t { Client, Server };
/** @brief Transaction type (INVITE or non-INVITE). */
enum class TxnType : uint8_t { Invite, NonInvite };

/** @brief Transport send callback signature (host, port, data). */
using SendFn = std::function<bool(const char* host, uint16_t port,
                                  const char* data, size_t len)>;

/** @brief Callbacks from transaction layer to transaction user. */
struct TxnCallbacks {
    /** Response delivered to client TU. */
    std::function<void(TxnId, const SipMessage&)> onResponse;
    /** New request delivered to server TU. */
    std::function<void(TxnId, const SipMessage&)> onRequest;
    /** Transaction termination callback (normal/timeout). */
    std::function<void(TxnId)>                    onTerminated;
};

/** @brief Internal transaction record tracked by TransactionLayer. */
struct Transaction {
    /** Unique transaction id. */
    TxnId    id       = 0;
    /** Client/server role. */
    TxnRole  role     = TxnRole::Client;
    /** INVITE/non-INVITE transaction type. */
    TxnType  type     = TxnType::NonInvite;
    /** Current FSM state. */
    TxnState state    = TxnState::NICT_Trying;
    /** Branch key. */
    Branch   branch;
    /** Call-ID key. */
    CallId   callId;
    /** Request method key. */
    Method   method   = Method::Unknown;
    /** CSeq number key. */
    uint32_t cseq     = 0;

    // Remote transport target
    /** Remote target hostname/IP. */
    Str<64>  remoteHost;
    /** Remote target port. */
    uint16_t remotePort = SIP_UDP_PORT;
    /** True for UDP transactions, false for TCP. */
    bool     isUdp      = true;

    // Saved request for retransmission (client) or last response (server)
    /** Serialized request cache for retransmit. */
    char     reqBuf[SIP_MAX_MSG];
    /** Valid bytes in reqBuf. */
    size_t   reqLen = 0;
    /** Serialized response cache for retransmit. */
    char     respBuf[SIP_MAX_MSG];
    /** Valid bytes in respBuf. */
    size_t   respLen = 0;

    // Timer fires (absolute ms). 0 = not armed.
    /** Timer A (ICT retransmit interval). */
    int64_t timerA = 0;   // retransmit interval (doubles each fire)
    /** Timer B (ICT total timeout). */
    int64_t timerB = 0;   // total timeout
    /** Timer D (ICT completed wait). */
    int64_t timerD = 0;   // wait-completed (ICT)
    /** Timer E (NICT retransmit). */
    int64_t timerE = 0;   // retransmit (NICT, starts at T1)
    /** Timer F (NICT timeout). */
    int64_t timerF = 0;   // timeout (NICT)
    /** Timer G (IST completed retransmit). */
    int64_t timerG = 0;   // retransmit (IST completed)
    /** Timer H (IST timeout). */
    int64_t timerH = 0;   // timeout (IST)
    /** Timer I (IST confirmed absorb). */
    int64_t timerI = 0;   // ACK absorb (IST confirmed)
    /** Timer J (NIST completed absorb). */
    int64_t timerJ = 0;   // completed absorb (NIST)
    /** Timer K (NICT completed absorb). */
    int64_t timerK = 0;   // completed absorb (NICT)

    /** Current retransmission interval (ms). */
    int32_t retransmitInterval = SIP_T1; // ms, doubles up to T2
};

/** @brief RFC3261 transaction state-machine manager. */
class TransactionLayer {
public:
    /** @brief Initialize send callback and TU callbacks. */
    void init(SendFn send, TxnCallbacks cbs);

    // Create and start client transaction. Returns InvalidTxn on pool exhaustion.
    /** @brief Create and start client transaction for outgoing request. */
    TxnId sendRequest(const SipMessage& req, const char* host, uint16_t port,
                      bool udp = true);

    // Feed an incoming parsed message (request or response).
    // Returns true if consumed by an existing transaction.
    /** @brief Feed parsed incoming request/response into transaction layer. */
    bool onMessage(const SipMessage& msg, const char* srcHost, uint16_t srcPort);

    /** @brief Send response on existing server transaction. */
    bool sendResponse(TxnId id, const SipMessage& resp);

    /** @brief Cancel in-progress INVITE client transaction. */
    bool cancelInvite(TxnId id);

    /** @brief Advance timers and run timeout/retransmit handling. */
    void tick(int64_t nowMs);

    /** @brief Find transaction by id for diagnostics/introspection. */
    const Transaction* findById(TxnId id) const;

private:
    Pool<Transaction, SIP_MAX_TXNS> pool_;
    SendFn       send_;
    TxnCallbacks cbs_;
    uint32_t     nextId_ = 1;

    static int64_t nowMs();

    Transaction* findByKey(const Branch& branch, Method method, TxnRole role) const;
    Transaction* findByIdM(TxnId id);

    void transmit(Transaction& t);        // (re)send reqBuf
    void transmitResp(Transaction& t);   // (re)send respBuf
    void terminate(Transaction& t);

    // Per-type FSM handlers
    void feedICT (Transaction& t, const SipMessage& msg);
    void feedNICT(Transaction& t, const SipMessage& msg);
    void feedIST (Transaction& t, const SipMessage& msg);
    void feedNIST(Transaction& t, const SipMessage& msg);

    void tickICT (Transaction& t, int64_t now);
    void tickNICT(Transaction& t, int64_t now);
    void tickIST (Transaction& t, int64_t now);
    void tickNIST(Transaction& t, int64_t now);
};

} // namespace sip
