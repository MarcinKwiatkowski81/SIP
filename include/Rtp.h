// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file Rtp.h
 * @brief RTP media session API with RFC4733 DTMF support.
 */
#pragma once
#include "common.h"
#include "Codec.h"
#include <functional>
#include <pthread.h>
#include <netinet/in.h>   // struct sockaddr_in

namespace sip {

/** @brief RTP fixed header (12 bytes, network byte order). */
#pragma pack(push,1)
struct RtpHdr {
    /** V/P/X/CC bitfield. */
    uint8_t  octet0;   // V(2) P(1) X(1) CC(4)
    /** M/PT bitfield. */
    uint8_t  octet1;   // M(1) PT(7)
    /** Sequence number (network order). */
    uint16_t seq;      // sequence number
    /** RTP timestamp (network order). */
    uint32_t ts;       // timestamp
    /** Synchronization source identifier (network order). */
    uint32_t ssrc;     // synchronisation source

    /** RTP version field. */
    uint8_t  version()   const { return (octet0>>6)&3; }
    /** Padding flag. */
    bool     padding()   const { return (octet0>>5)&1; }
    /** Header extension flag. */
    bool     extension() const { return (octet0>>4)&1; }
    /** CSRC count field. */
    uint8_t  csrcCount() const { return octet0&0x0F; }
    /** Marker bit. */
    bool     marker()    const { return (octet1>>7)&1; }
    /** Payload type field. */
    uint8_t  pt()        const { return octet1&0x7F; }
    /** Sequence number in host order. */
    uint16_t seqH()      const; // host order
    /** RTP timestamp in host order. */
    uint32_t tsH()       const; // host order
    /** SSRC in host order. */
    uint32_t ssrcH()     const; // host order

    /** Initialize all RTP header fields. */
    void init(uint8_t pt, bool marker, uint16_t seq,
              uint32_t ts, uint32_t ssrc);
};
#pragma pack(pop)
static_assert(sizeof(RtpHdr)==12);

/** @brief RFC4733 telephone-event payload (4 bytes). */
#pragma pack(push,1)
struct DtmfPayload {
    /** Event code (digits typically 0-15). */
    uint8_t  event;       // digit 0-15
    /** End/reserved/volume bitfield. */
    uint8_t  eRvolume;    // E(1) R(1) volume(6)
    /** Event duration in RTP timestamp units. */
    uint16_t duration;    // in timestamp units

    /** True when event end bit is set. */
    bool endBit() const { return (eRvolume>>7)&1; }
    /** Set/clear event end bit. */
    void setEnd(bool e)  { eRvolume = (eRvolume & 0x7F) | (e?0x80:0); }
};
#pragma pack(pop)
static_assert(sizeof(DtmfPayload)==4);

/** @brief Decoded PCM frame callback payload. */
struct AudioFrame {
    /** PCM sample pointer. */
    const int16_t* pcm;
    /** Number of PCM samples. */
    size_t         samples;
    /** Source SSRC. */
    uint32_t       ssrc;
    /** RTP timestamp associated with frame. */
    uint32_t       timestamp;
};

/** @brief RTP callback set for audio/DTMF/raw packet hooks. */
struct RtpCallbacks {
    /** Called for decoded audio frames. */
    std::function<void(const AudioFrame&)>               onAudio;
    /** Called for completed RFC4733 DTMF events. */
    std::function<void(uint8_t digit, uint16_t durMs)>   onDtmf;
    /** Optional raw RTP packet callback. */
    std::function<void(const uint8_t*, size_t)>          onRawRtp;  // optional
};

/** @brief Single RTP media session with receive thread and basic stats. */
class RtpSession {
public:
    /** @brief Runtime RTP session configuration. */
    struct Config {
        /** Local SSRC (`0` means auto-generate random SSRC). */
        uint32_t ssrc      = 0;   // 0 → random
        /** Primary outbound payload type. */
        uint8_t  pt        = 0;   // primary payload type
        /** Telephone-event payload type. */
        uint8_t  dtmfPT    = 101; // telephone-event PT
        /** Packetization time in milliseconds. */
        uint32_t ptime     = 20;  // ms per packet
        /** Enable DTMF support. */
        bool     dtmf      = true;
    };

    /**
     * @brief Open RTP session socket and start receive loop thread.
     */
    bool open(const char* localAddr, uint16_t localPort,
              const char* remoteAddr, uint16_t remotePort,
              ICodec* codec, const Config& cfg, RtpCallbacks cbs);
    /** @brief Close RTP session and join receive thread. */
    void close();
    /** @brief True when RTP socket is open. */
    bool isOpen() const { return fd_ >= 0; }

    /** @brief Replace callbacks at runtime (thread-safe). */
    void setCallbacks(RtpCallbacks cbs) {
        pthread_mutex_lock(&cbsMu_);
        cbs_ = std::move(cbs);
        pthread_mutex_unlock(&cbsMu_);
    }

    /** @brief Encode and send one PCM audio frame. */
    bool sendAudio(const int16_t* pcm, size_t samples);

    /** @brief Send RFC4733 DTMF event sequence. */
    bool sendDtmf(uint8_t digit, uint16_t durationMs = 160);

    /** @brief Runtime RTP transmit/receive statistics. */
    struct Stats {
        /** Transmitted RTP packet count. */
        uint64_t txPkts=0;
        /** Received RTP packet count. */
        uint64_t rxPkts=0;
        /** Transmitted byte counter. */
        uint64_t txBytes=0;
        /** Received byte counter. */
        uint64_t rxBytes=0;
        /** Estimated missing sequence count. */
        uint32_t rxLost=0;
        /** Estimated interarrival jitter in milliseconds. */
        double   jitterMs=0;
    };
    /** @brief Return current RTP stats snapshot. */
    Stats stats() const { return stats_; }

private:
    int              fd_      = -1;
    ICodec*          codec_   = nullptr;
    Config           cfg_;
    RtpCallbacks     cbs_;
    pthread_mutex_t  cbsMu_   = PTHREAD_MUTEX_INITIALIZER;
    struct sockaddr_in remote_ = {};   // sendto target (no connect() filter)

    uint32_t ssrc_;
    uint16_t txSeq_    = 0;
    uint32_t txTs_     = 0;

    // Receive side
    uint16_t rxExpSeq_ = 0;
    bool     rxInit_   = false;
    // Jitter estimation (RFC 3550 §A.8)
    double   jitter_   = 0.0;
    uint32_t rxLastTs_ = 0;
    int64_t  rxLastWall_= 0;

    Stats    stats_    = {};

    // Receive thread
    pthread_t recvTid_;
    bool      recvRun_ = false;

    static void* recvThread(void* arg);
    void  recvLoop();
    void  handlePacket(const uint8_t* buf, size_t len);
    bool  sendRtp(const uint8_t* payload, size_t payLen,
                  uint8_t pt, bool marker);
};

} // namespace sip
