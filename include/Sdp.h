// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file Sdp.h
 * @brief SDP session model and Offer/Answer helpers.
 */
#pragma once
#include "common.h"
#include "Codec.h"

namespace sip {

/** @brief SDP media type token. */
enum class MediaType : uint8_t { Audio=0, Video, Text, Application };
/** @brief SDP media direction attribute. */
enum class MediaDir  : uint8_t { SendRecv=0, SendOnly, RecvOnly, Inactive };

/** @brief One codec mapping entry from m=/a=rtpmap lines. */
struct RtpMap {
    /** Payload type value (255 = unused slot). */
    uint8_t  pt        = 255;   // 255 = unused slot
    /** Encoding name (PCMU/PCMA/telephone-event). */
    Str<16>  encoding;          // "PCMU", "PCMA", "telephone-event"
    /** RTP clock rate in Hz. */
    uint32_t clockRate = 8000;
    /** Channel count (typically 1 for narrowband voice). */
    uint8_t  channels  = 1;
    /** Optional fmtp parameter value. */
    Str<64>  fmtp;              // a=fmtp value

    /** @brief True when entry contains valid payload type. */
    bool valid() const { return pt != 255; }
};

/** @brief One SDP media section (m= block). */
struct MediaSection {
    /** Media type for this section. */
    MediaType type       = MediaType::Audio;
    /** Media transport port. */
    uint16_t  port       = 0;
    /** Transport protocol token (e.g. RTP/AVP). */
    Str<16>   proto;            // "RTP/AVP"
    /** Direction attribute for this media. */
    MediaDir  dir        = MediaDir::SendRecv;
    /** Optional media-level connection address override. */
    Str<64>   connAddr;         // c= override; empty → use session c=
    /** Offered/accepted codecs for this media. */
    RtpMap    codecs[SIP_MAX_CODECS];
    /** Number of valid codec entries. */
    uint8_t   codecCount = 0;

    /** @brief Find codec by payload type. */
    const RtpMap* findByPT(uint8_t pt)      const;
    /** @brief Find codec by encoding name (case-insensitive). */
    const RtpMap* findByName(const char* n) const;
    /** @brief Append codec entry to media section. */
    bool addCodec(const RtpMap& r) {
        if (codecCount >= SIP_MAX_CODECS) return false;
        codecs[codecCount++] = r; return true;
    }
};

/** @brief Parsed SDP session body. */
struct SdpSession {
    /** SDP version (v=). */
    uint32_t    version    = 0;      // v=
    /** Origin username (o=). */
    Str<32>     originUser;          // o= username
    /** Origin session id (o=). */
    uint64_t    sessionId  = 0;      // o= sess-id
    /** Origin session version (o=). */
    uint64_t    sessionVer = 0;      // o= sess-version
    /** Session-level connection address (c=). */
    Str<40>     connAddr;            // c= connection address
    /** Session name (s=). */
    Str<64>     sessionName;         // s=

    /** Media sections in session description. */
    MediaSection media[SIP_MAX_MEDIA];
    /** Number of valid media sections. */
    uint8_t      mediaCount = 0;

    // ── Parse ─────────────────────────────────────────────────────────────────
    /** @brief Parse SDP body text into SdpSession model. */
    static Result<SdpSession> parse(const char* data, size_t len);

    // ── Serialize ─────────────────────────────────────────────────────────────
    /** @brief Serialize SDP text. Returns bytes written (excluding NUL). */
    size_t format(char* buf, size_t sz) const;

    // ── Offer/Answer (RFC 3264) ────────────────────────────────────────────────
    /** @brief Build offer from local codec registry and RTP endpoint. */
    static SdpSession makeOffer(const CodecRegistry& reg,
                                const char* localAddr, uint16_t rtpPort,
                                bool includeVideo = false);

    /** @brief Build answer selecting intersection with offered codecs. */
    static SdpSession makeAnswer(const SdpSession& offer,
                                 const CodecRegistry& reg,
                                 const char* localAddr, uint16_t rtpPort);

    /** @brief Return first audio media section, or nullptr. */
    const MediaSection* audioMedia() const;
    /** @brief Mutable first audio media section, or nullptr. */
    MediaSection*       audioMediaMut();

    /** @brief Return negotiated codec candidate from first audio section. */
    const RtpMap* negotiatedCodec() const;
};

} // namespace sip
