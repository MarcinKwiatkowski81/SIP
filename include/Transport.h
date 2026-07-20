// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file Transport.h
 * @brief SIP UDP/TCP transport abstraction.
 *
 * Provides one UDP socket plus one TCP listen socket on the same SIP port.
 * TCP connections are pooled and deliver assembled SIP messages through a
 * unified receive callback.
 */
#pragma once
#include "common.h"
#include <functional>
#include <pthread.h>

namespace sip {

/**
 * @brief Receive callback invoked by UDP or TCP reader threads.
 *
 * `data` is valid only for callback duration.
 */
using RecvFn = std::function<void(const char* data, size_t len,
                                  const char* srcHost, uint16_t srcPort,
                                  bool isTcp)>;

/** @brief SIP transport protocol selector. */
enum class Proto : uint8_t { Udp = 0, Tcp };

/** @brief Per-peer TCP connection pool slot. */
struct TcpConn {
    /** Connected socket fd, or -1 when unused. */
    int      fd            = -1;
    /** Peer host string. */
    char     peerHost[48]  = {};
    /** Peer TCP port. */
    uint16_t peerPort      = 0;
    /** True if accepted inbound, false if outbound. */
    bool     inbound       = false;
    /** True when this pool slot is allocated. */
    bool     used          = false;
    /** Partial receive buffer for SIP over TCP framing. */
    char     rbuf[SIP_MAX_MSG]; // partial-message accumulation buffer
    /** Bytes currently stored in rbuf. */
    size_t   rlen          = 0;
    /** Reader thread handle for this connection. */
    pthread_t tid;
    /** Whether reader thread is running. */
    bool      tidRunning   = false;
    /** Write mutex for socket send serialization. */
    pthread_mutex_t wmu    = PTHREAD_MUTEX_INITIALIZER;
};

/** @brief SIP transport facade for UDP and TCP operations. */
class Transport {
public:
    /** Maximum pooled TCP connections. */
    static constexpr int MAX_TCP = 32;

    /** @brief Transport opening options. */
    struct Config {
        /** Local bind address (`nullptr` => INADDR_ANY). */
        const char* localAddr = nullptr;   // nullptr -> INADDR_ANY
        /** SIP listen port used by UDP/TCP. */
        uint16_t    port      = SIP_UDP_PORT;
        /** Enable UDP socket and reader thread. */
        bool        enableUdp = true;
        /** Enable TCP listen socket and accept loop. */
        bool        enableTcp = true;
    };

    /** @brief Open requested transport sockets and start reader threads. */
    bool open(const Config& cfg, RecvFn onRecv);
    /** @brief Close sockets and stop all transport threads. */
    void close();
    /** @brief True when UDP or TCP transport is currently open. */
    bool isOpen()  const { return udpFd_ >= 0 || tcpListenFd_ >= 0; }
    /** @brief Configured SIP port. */
    uint16_t port() const { return cfg_.port; }

    /** @brief Send SIP bytes via selected transport. */
    bool send(const char* data, size_t len,
              const char* dstHost, uint16_t dstPort, Proto proto);
    /** @brief Send SIP bytes over UDP. */
    bool sendUdp(const char* data, size_t len,
                 const char* dstHost, uint16_t dstPort);
    /** @brief Send SIP bytes over TCP (connect lazily if needed). */
    bool sendTcp(const char* data, size_t len,
                 const char* dstHost, uint16_t dstPort);

    /** @brief Convert Via transport token to Proto (`TCP`/`UDP`/`TLS`). */
    static Proto protoFromVia(const char* transport);   // "TCP"/"UDP"/"TLS"->Proto

private:
    Config   cfg_          = {};
    RecvFn   onRecv_;
    int      udpFd_        = -1;
    int      tcpListenFd_  = -1;
    volatile bool running_ = false;
    pthread_t udpTid_;
    pthread_t tcpAcceptTid_;
    TcpConn  conns_[MAX_TCP];
    pthread_mutex_t poolMu_ = PTHREAD_MUTEX_INITIALIZER;

    static void* udpThreadFn(void*);
    void udpLoop();
    static void* tcpAcceptFn(void*);
    void tcpAcceptLoop();
    struct ConnThread { Transport* self; TcpConn* conn; };
    static void* tcpReadFn(void*);
    void tcpReadLoop(TcpConn* c);

    TcpConn* findConn(const char* host, uint16_t port);  // must hold poolMu_
    TcpConn* getOrConnect(const char* host, uint16_t port);
    TcpConn* allocConn();          // must hold poolMu_
    void     releaseConn(TcpConn* c); // must hold poolMu_
    size_t   dispatchTcpBuf(TcpConn* c);
    bool     sendOnFd(int fd, const char* data, size_t len);
};

} // namespace sip
