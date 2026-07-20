// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// Transport.cpp – UDP + TCP dual-transport for SIP (RFC 3261 §18)
#include "Transport.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <algorithm>

namespace sip {

// ── Helpers ───────────────────────────────────────────────────────────────────
static bool setReuseAddr(int fd) {
    int one = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0;
}
static void setRecvTimeout(int fd, int ms) {
    struct timeval tv{ ms/1000, (ms%1000)*1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}
static sockaddr_in makeSA(const char* host, uint16_t port) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    sa.sin_addr.s_addr = (host && *host) ? inet_addr(host) : INADDR_ANY;
    return sa;
}

// ── open ──────────────────────────────────────────────────────────────────────
bool Transport::open(const Config& cfg, RecvFn onRecv) {
    cfg_    = cfg;
    onRecv_ = onRecv;
    running_= true;

    if (cfg_.enableUdp) {
        udpFd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (udpFd_ < 0) { perror("UDP socket"); return false; }
        setReuseAddr(udpFd_);
        setRecvTimeout(udpFd_, 200);
        auto sa = makeSA(cfg_.localAddr, cfg_.port);
        if (bind(udpFd_, (sockaddr*)&sa, sizeof sa) < 0) {
            perror("UDP bind"); ::close(udpFd_); udpFd_=-1; return false;
        }
        pthread_create(&udpTid_, nullptr, udpThreadFn, this);
        printf("[TRANSPORT] UDP  %s:%u\n",
               cfg_.localAddr ? cfg_.localAddr : "*", cfg_.port);
    }

    if (cfg_.enableTcp) {
        tcpListenFd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (tcpListenFd_ < 0) { perror("TCP socket"); return false; }
        setReuseAddr(tcpListenFd_);
        setRecvTimeout(tcpListenFd_, 200);
        auto sa = makeSA(cfg_.localAddr, cfg_.port);
        if (bind(tcpListenFd_, (sockaddr*)&sa, sizeof sa) < 0) {
            perror("TCP bind"); ::close(tcpListenFd_); tcpListenFd_=-1; return false;
        }
        if (listen(tcpListenFd_, 8) < 0) {
            perror("TCP listen"); ::close(tcpListenFd_); tcpListenFd_=-1; return false;
        }
        pthread_create(&tcpAcceptTid_, nullptr, tcpAcceptFn, this);
        printf("[TRANSPORT] TCP  %s:%u\n",
               cfg_.localAddr ? cfg_.localAddr : "*", cfg_.port);
    }
    return true;
}

// ── close ─────────────────────────────────────────────────────────────────────
void Transport::close() {
    running_ = false;
    if (udpFd_ >= 0) {
        ::shutdown(udpFd_, SHUT_RDWR);
        pthread_join(udpTid_, nullptr);
        ::close(udpFd_); udpFd_ = -1;
    }
    if (tcpListenFd_ >= 0) {
        ::shutdown(tcpListenFd_, SHUT_RDWR);
        pthread_join(tcpAcceptTid_, nullptr);
        ::close(tcpListenFd_); tcpListenFd_ = -1;
    }
    pthread_mutex_lock(&poolMu_);
    for (auto& c : conns_) {
        if (c.used && c.fd >= 0) { ::shutdown(c.fd,SHUT_RDWR); ::close(c.fd); c.fd=-1; }
    }
    pthread_mutex_unlock(&poolMu_);
    for (auto& c : conns_) {
        if (c.tidRunning) { pthread_join(c.tid, nullptr); c.tidRunning=false; }
        c.used = false;
    }
}

// ── send ──────────────────────────────────────────────────────────────────────
bool Transport::send(const char* data, size_t len,
                     const char* host, uint16_t port, Proto proto) {
    return (proto == Proto::Tcp) ? sendTcp(data,len,host,port)
                                 : sendUdp(data,len,host,port);
}

bool Transport::sendUdp(const char* data, size_t len,
                        const char* host, uint16_t port) {
    if (udpFd_ < 0) return false;
    auto sa = makeSA(host, port);
    return sendto(udpFd_, data, (int)len, 0, (sockaddr*)&sa, sizeof sa)
           == (ssize_t)len;
}

bool Transport::sendOnFd(int fd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, data+sent, len-sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

bool Transport::sendTcp(const char* data, size_t len,
                        const char* host, uint16_t port) {
    TcpConn* c = getOrConnect(host, port);
    if (!c) return false;
    pthread_mutex_lock(&c->wmu);
    bool ok = sendOnFd(c->fd, data, len);
    pthread_mutex_unlock(&c->wmu);
    if (!ok) {
        pthread_mutex_lock(&poolMu_);
        releaseConn(c);
        pthread_mutex_unlock(&poolMu_);
    }
    return ok;
}

// ── Connection pool ───────────────────────────────────────────────────────────
TcpConn* Transport::allocConn() {
    for (auto& c : conns_) if (!c.used) { c.used=true; c.rlen=0; return &c; }
    return nullptr;
}
void Transport::releaseConn(TcpConn* c) {
    if (c->fd >= 0) { ::shutdown(c->fd,SHUT_RDWR); ::close(c->fd); c->fd=-1; }
    c->used = false; c->rlen = 0;
    memset(c->peerHost, 0, sizeof c->peerHost); c->peerPort=0;
}
TcpConn* Transport::findConn(const char* host, uint16_t port) {
    for (auto& c : conns_)
        if (c.used && c.fd>=0 && c.peerPort==port && strcmp(c.peerHost,host)==0)
            return &c;
    return nullptr;
}
TcpConn* Transport::getOrConnect(const char* host, uint16_t port) {
    pthread_mutex_lock(&poolMu_);
    TcpConn* c = findConn(host, port);
    if (c) { pthread_mutex_unlock(&poolMu_); return c; }
    c = allocConn();
    if (!c) { pthread_mutex_unlock(&poolMu_); return nullptr; }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { c->used=false; pthread_mutex_unlock(&poolMu_); return nullptr; }
    setReuseAddr(fd);
    auto sa = makeSA(host, port);
    if (::connect(fd, (sockaddr*)&sa, sizeof sa) < 0) {
        perror("TCP connect"); ::close(fd); c->used=false;
        pthread_mutex_unlock(&poolMu_); return nullptr;
    }
    c->fd=fd; c->peerPort=port; c->inbound=false;
    strncpy(c->peerHost, host, sizeof c->peerHost-1);
    auto* arg = new ConnThread{this, c};
    c->tidRunning = true;
    pthread_create(&c->tid, nullptr, tcpReadFn, arg);
    printf("[TRANSPORT] TCP connected -> %s:%u\n", host, port);
    pthread_mutex_unlock(&poolMu_);
    return c;
}

// ── UDP receive thread ────────────────────────────────────────────────────────
void* Transport::udpThreadFn(void* a) { ((Transport*)a)->udpLoop(); return nullptr; }
void Transport::udpLoop() {
    char buf[SIP_MAX_MSG];
    sockaddr_in src; socklen_t sl=sizeof src;
    while (running_) {
        ssize_t n = recvfrom(udpFd_, buf, sizeof buf-1, 0, (sockaddr*)&src, &sl);
        if (n<=0) continue;
        buf[n]=0;
        char host[48]; inet_ntop(AF_INET, &src.sin_addr, host, sizeof host);
        onRecv_(buf,(size_t)n,host,ntohs(src.sin_port),false);
    }
}

// ── TCP accept thread ─────────────────────────────────────────────────────────
void* Transport::tcpAcceptFn(void* a) { ((Transport*)a)->tcpAcceptLoop(); return nullptr; }
void Transport::tcpAcceptLoop() {
    while (running_) {
        sockaddr_in src; socklen_t sl=sizeof src;
        int fd = accept(tcpListenFd_, (sockaddr*)&src, &sl);
        if (fd < 0) continue;
        char host[48]; inet_ntop(AF_INET, &src.sin_addr, host, sizeof host);
        uint16_t port = ntohs(src.sin_port);
        printf("[TRANSPORT] TCP accepted <- %s:%u\n", host, port);
        pthread_mutex_lock(&poolMu_);
        TcpConn* c = allocConn();
        if (!c) { ::close(fd); pthread_mutex_unlock(&poolMu_); continue; }
        c->fd=fd; c->peerPort=port; c->inbound=true;
        strncpy(c->peerHost, host, sizeof c->peerHost-1);
        auto* arg = new ConnThread{this, c};
        c->tidRunning = true;
        pthread_create(&c->tid, nullptr, tcpReadFn, arg);
        pthread_mutex_unlock(&poolMu_);
    }
}

// ── TCP per-connection read thread ────────────────────────────────────────────
void* Transport::tcpReadFn(void* a) {
    auto* ct=(ConnThread*)a; ct->self->tcpReadLoop(ct->conn); delete ct; return nullptr;
}
void Transport::tcpReadLoop(TcpConn* c) {
    setRecvTimeout(c->fd, 200);
    char host[48]; strncpy(host, c->peerHost, sizeof host);
    uint16_t port = c->peerPort;
    while (running_ && c->fd >= 0) {
        size_t space = sizeof(c->rbuf) - c->rlen - 1;
        if (!space) { c->rlen=0; continue; }
        ssize_t n = recv(c->fd, c->rbuf+c->rlen, space, 0);
        if (n <= 0) {
            if (errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR) continue;
            break;
        }
        c->rlen += (size_t)n;
        c->rbuf[c->rlen] = 0;
        size_t consumed = dispatchTcpBuf(c);
        if (consumed && consumed < c->rlen)
            memmove(c->rbuf, c->rbuf+consumed, c->rlen-consumed);
        c->rlen -= std::min(consumed, c->rlen);
    }
    printf("[TRANSPORT] TCP closed %s:%u\n", host, port);
    pthread_mutex_lock(&poolMu_);
    releaseConn(c);
    pthread_mutex_unlock(&poolMu_);
    c->tidRunning = false;
}

// ── TCP message framing (RFC 3261 §18.3) ─────────────────────────────────────
size_t Transport::dispatchTcpBuf(TcpConn* c) {
    size_t consumed = 0;
    while (true) {
        const char* buf = c->rbuf + consumed;
        size_t      len = c->rlen - consumed;
        if (!len) break;

        // Find \r\n\r\n or \n\n header terminator
        const char* sep = nullptr;
        for (size_t i=0; i+1<len; ++i) {
            if (i+3<len && buf[i]=='\r'&&buf[i+1]=='\n'&&buf[i+2]=='\r'&&buf[i+3]=='\n')
                { sep=buf+i+4; break; }
            if (buf[i]=='\n'&&buf[i+1]=='\n')
                { sep=buf+i+2; break; }
        }
        if (!sep) break;   // incomplete headers

        size_t hdrLen = (size_t)(sep-buf);

        // Find Content-Length (or compact "l:")
        size_t bodyLen = 0;
        size_t i = 0;
        while (i < hdrLen) {
            const char* line = buf+i;
            size_t left = hdrLen-i;
            if (left>=15 && strncasecmp(line,"Content-Length:",15)==0) {
                bodyLen=(size_t)strtoul(line+15,nullptr,10); break;
            }
            if (left>=2 && (line[0]=='l'||line[0]=='L') && line[1]==':') {
                bodyLen=(size_t)strtoul(line+2,nullptr,10); break;
            }
            const char* nl=(const char*)memchr(line,'\n',left);
            if (!nl) break;
            i=(size_t)(nl-buf)+1;
        }

        size_t msgLen = hdrLen + bodyLen;
        if (msgLen > len) break;   // body incomplete
        onRecv_(buf, msgLen, c->peerHost, c->peerPort, true);
        consumed += msgLen;
    }
    return consumed;
}

// ── protoFromVia ──────────────────────────────────────────────────────────────
Proto Transport::protoFromVia(const char* t) {
    if (t && strncasecmp(t,"TCP",3)==0) return Proto::Tcp;
    return Proto::Udp;
}

} // namespace sip
