// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// Rtp.cpp – RTP send/receive (RFC 3550) + DTMF (RFC 4733)
#include "Rtp.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <cerrno>

namespace sip {

// ── RtpHdr ───────────────────────────────────────────────────────────────────
uint16_t RtpHdr::seqH()  const { return ntohs(seq);  }
uint32_t RtpHdr::tsH()   const { return ntohl(ts);   }
uint32_t RtpHdr::ssrcH() const { return ntohl(ssrc); }
void RtpHdr::init(uint8_t pt, bool marker, uint16_t s, uint32_t t, uint32_t sr) {
    octet0=0x80;           // V=2, P=0, X=0, CC=0
    octet1=(uint8_t)((pt&0x7F)|(marker?0x80:0));
    seq  =htons(s);
    ts   =htonl(t);
    ssrc =htonl(sr);
}

static int64_t msNow() { struct timeval tv; gettimeofday(&tv,nullptr); return (int64_t)tv.tv_sec*1000+tv.tv_usec/1000; }

// ── open ──────────────────────────────────────────────────────────────────────
bool RtpSession::open(const char* localAddr, uint16_t localPort,
                      const char* remoteAddr, uint16_t remotePort,
                      ICodec* codec, const Config& cfg, RtpCallbacks cbs) {
    if(fd_>=0) close();
    codec_=codec; cfg_=cfg; cbs_=cbs;
    ssrc_=cfg.ssrc ? cfg.ssrc : ((uint32_t)rand()^(uint32_t)rand());
    txSeq_=0; txTs_=0; rxInit_=false; jitter_=0; stats_={};

    fd_=socket(AF_INET,SOCK_DGRAM,0);
    if(fd_<0) return false;

    // SO_REUSEPORT lets a second sniff socket (e.g. recorder) share this port.
    // SO_REUSEADDR prevents TIME_WAIT bind failures on restart.
    int one=1;
    setsockopt(fd_,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    setsockopt(fd_,SOL_SOCKET,SO_REUSEPORT,&one,sizeof one);
    // Receive timeout so the recv thread can observe recvRun_ and exit cleanly.
    struct timeval rtv={0,50000};  // 50 ms
    setsockopt(fd_,SOL_SOCKET,SO_RCVTIMEO,&rtv,sizeof rtv);

    // Bind local
    struct sockaddr_in la={}; la.sin_family=AF_INET; la.sin_port=htons(localPort);
    la.sin_addr.s_addr=localAddr&&*localAddr?inet_addr(localAddr):INADDR_ANY;
    if(bind(fd_,(struct sockaddr*)&la,sizeof la)<0){ ::close(fd_); fd_=-1; return false; }

    // Store remote address for sendto(); do NOT call connect().
    // connect() would filter incoming packets to only those from the exact
    // source IP:port, which breaks reception when Asterisk uses rtp_symmetric
    // or when the media proxy sends from a port differing from the SDP m= line.
    // Using sendto() + unconnected recv gives full bidirectional compatibility.
    memset(&remote_,0,sizeof remote_);
    remote_.sin_family      = AF_INET;
    remote_.sin_port        = htons(remotePort);
    remote_.sin_addr.s_addr = inet_addr(remoteAddr);
    // Debug: uncomment to trace RTP endpoint negotiation
    // printf("[RTP] open local=%s:%u  remote=%s:%u\n",
    //        localAddr?localAddr:"0.0.0.0", localPort, remoteAddr, remotePort);

    // Recv thread
    recvRun_=true;
    if(pthread_create(&recvTid_,nullptr,recvThread,this)!=0){
        ::close(fd_); fd_=-1; recvRun_=false; return false;
    }
    return true;
}

void RtpSession::close() {
    if(fd_<0) return;
    recvRun_=false;
    // Join FIRST: the recv thread runs until recvRun_=false is observed, which
    // happens within SO_RCVTIMEO (50 ms) at most.  During that window it still
    // processes any packets already queued in the kernel socket buffer, so we
    // don't lose the last 50-150 ms of audio at hang-up.
    // Only close the fd AFTER the thread has exited — closing it before join
    // would wake recv() with EBADF, causing the thread to exit immediately and
    // silently discard all buffered packets.
    pthread_join(recvTid_,nullptr);
    ::close(fd_); fd_=-1;
}

// ── send ──────────────────────────────────────────────────────────────────────
bool RtpSession::sendRtp(const uint8_t* payload, size_t payLen, uint8_t pt, bool marker) {
    if(fd_<0) return false;
    uint8_t pkt[SIP_MAX_MSG];
    if(sizeof(RtpHdr)+payLen>sizeof pkt) return false;
    RtpHdr* h=(RtpHdr*)pkt;
    h->init(pt,marker,txSeq_++,txTs_,ssrc_);
    memcpy(pkt+sizeof(RtpHdr),payload,payLen);
    ssize_t sent=sendto(fd_,(const char*)pkt,sizeof(RtpHdr)+payLen,0,
                         (const struct sockaddr*)&remote_,sizeof remote_);
    if(sent>0){ ++stats_.txPkts; stats_.txBytes+=(uint64_t)sent; }
    return sent>0;
}

bool RtpSession::sendAudio(const int16_t* pcm, size_t samples) {
    if(!codec_||fd_<0) return false;
    uint8_t enc[SIP_MAX_MSG];
    size_t encLen=codec_->encode(pcm,samples,enc,sizeof enc);
    if(!encLen) return false;
    bool ok=sendRtp(enc,encLen,cfg_.pt,false);
    txTs_+=codec_->clockRate()/50; // advance by 20ms
    return ok;
}

bool RtpSession::sendDtmf(uint8_t digit, uint16_t durationMs) {
    if(fd_<0) return false;
    uint16_t dur=(uint16_t)((uint32_t)durationMs*8); // samples at 8kHz
    uint32_t evTs=txTs_; // same timestamp for all packets of one event
    // Send begin + two end packets (RFC 4733 §2.5)
    DtmfPayload dp={};
    dp.event=digit&0x0F; dp.eRvolume=10; // 10 dBm0 volume
    for(int pkt=0;pkt<3;++pkt) {
        dp.duration=htons(dur);
        bool end=(pkt>=1); dp.setEnd(end);
        // Temporarily set txTs_ to evTs so RTP header uses same ts
        uint32_t savedTs=txTs_; txTs_=evTs;
        sendRtp((const uint8_t*)&dp,sizeof dp,cfg_.dtmfPT,pkt==0);
        txTs_=savedTs;
        if(pkt<2) { struct timespec ts={0,20*1000*1000L}; nanosleep(&ts,nullptr); }
    }
    txTs_+=dur;
    return true;
}

// ── receive ───────────────────────────────────────────────────────────────────
void* RtpSession::recvThread(void* arg) {
    ((RtpSession*)arg)->recvLoop(); return nullptr;
}

void RtpSession::recvLoop() {
    uint8_t buf[SIP_MAX_MSG];
    while(recvRun_) {
        ssize_t n=recv(fd_,(char*)buf,sizeof buf,0);
        if(n<0) {
            if(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR) continue;
            break;
        }
        if(n==0) break;
        handlePacket(buf,(size_t)n);
    }
    // ── End-of-stream drain ─────────────────────────────────────────
    // After recvRun_=false the remote may still send a few packets:
    //   • BYE has been sent but not yet processed by the remote (~1 ms LAN)
    //   • Packets already queued in the kernel socket buffer
    // Strategy: keep receiving with a short per-call timeout; exit only after
    // two consecutive timeouts (= no packet for 2×50 ms = 100 ms of silence),
    // which reliably signals end-of-stream on both LAN and moderate-RTT WAN.
    if(fd_>=0) {
        struct timeval dtv={0,50000};          // 50 ms per recv() call
        setsockopt(fd_,SOL_SOCKET,SO_RCVTIMEO,&dtv,sizeof dtv);
        uint8_t tail[SIP_MAX_MSG]; ssize_t tn;
        int consec=0;
        while(consec<2) {                      // two dry windows → done
            tn=recv(fd_,tail,sizeof tail,0);
            if(tn>0)  { handlePacket(tail,(size_t)tn); consec=0; }
            else if(tn<0&&(errno==EAGAIN||errno==EWOULDBLOCK)) consec++;
            else break;                        // fd closed or real error
        }
    }
}

void RtpSession::handlePacket(const uint8_t* buf, size_t len) {
    if(len<sizeof(RtpHdr)) return;
    const RtpHdr* h=(const RtpHdr*)buf;
    if(h->version()!=2) return;
    ++stats_.rxPkts; stats_.rxBytes+=len;
    uint8_t pt=h->pt();
    const uint8_t* payload=buf+sizeof(RtpHdr)+h->csrcCount()*4;
    size_t payLen=len-sizeof(RtpHdr)-h->csrcCount()*4;
    if(payload+payLen>buf+len) return;

    // Snapshot callbacks under lock so setCallbacks() is safe
    pthread_mutex_lock(&cbsMu_);
    RtpCallbacks cbs = cbs_;
    pthread_mutex_unlock(&cbsMu_);

    if(cbs.onRawRtp) cbs.onRawRtp(buf,len);

    // RFC 4733 telephone-event
    // RFC 4733 §2.5: the sender MUST retransmit the end-bit packet three times
    // (for redundancy) using the same RTP timestamp for all packets of one event.
    // Guard with the event timestamp so only the first end-bit fires onDtmf.
    if(pt==cfg_.dtmfPT && payLen>=sizeof(DtmfPayload)) {
        const DtmfPayload* dp=(const DtmfPayload*)payload;
        if(dp->endBit() && cbs.onDtmf) {
            uint32_t evTs = h->tsH();
            if(!dtmfFired_ || evTs != dtmfLastTs_) {
                dtmfLastTs_ = evTs;
                dtmfFired_  = true;
                uint16_t dur=ntohs(dp->duration);
                cbs.onDtmf(dp->event, (uint16_t)((uint32_t)dur*1000/8000));
            }
        }
        return;
    }

    // Sequence tracking
    uint16_t seq=h->seqH();
    if(rxInit_) {
        int16_t diff=(int16_t)(seq-rxExpSeq_);
        if(diff>0) stats_.rxLost+=(uint32_t)diff;
        // Jitter estimate (RFC 3550 §A.8)
        int64_t now=msNow();
        if(rxLastWall_) {
            int64_t wallDelta=now-rxLastWall_;
            int64_t rtpDelta =(int64_t)((int32_t)(h->tsH()-rxLastTs_))*1000/(int64_t)codec_->clockRate();
            double d=(double)(wallDelta-rtpDelta); if(d<0) d=-d;
            jitter_+=( d - jitter_)/16.0;
            stats_.jitterMs=jitter_;
        }
        rxLastWall_=now; rxLastTs_=h->tsH();
    } else { rxInit_=true; rxLastWall_=msNow(); rxLastTs_=h->tsH(); }
    rxExpSeq_=(uint16_t)(seq+1);

    // Decode
    if(!codec_) return;
    static int16_t pcm[1024];
    size_t samples=codec_->decode(payload,payLen,pcm,sizeof(pcm)/sizeof(pcm[0]));
    if(samples&&cbs.onAudio)
        cbs.onAudio({pcm,samples,h->ssrcH(),h->tsH()});
}

} // namespace sip
