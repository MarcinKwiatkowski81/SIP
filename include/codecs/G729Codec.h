// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file G729Codec.h
 * @brief G.729A codec wrapper.
 */
#pragma once
#include "Codec.h"
#ifdef HAVE_BCG729
extern "C" {
    // bcg729 opaque handles
    typedef struct bcg729EncoderChannelContextStruct_struct Bcg729EncoderChannelContextStruct;
    typedef struct bcg729DecoderChannelContextStruct_struct Bcg729DecoderChannelContextStruct;
    Bcg729EncoderChannelContextStruct* initBcg729EncoderChannel(uint8_t enableVAD);
    Bcg729DecoderChannelContextStruct* initBcg729DecoderChannel(void);
    void closeBcg729EncoderChannel(Bcg729EncoderChannelContextStruct*);
    void closeBcg729DecoderChannel(Bcg729DecoderChannelContextStruct*);
    // Encode 80 int16 PCM samples -> 10 bytes. SIDFlag set if comfort noise.
    void bcg729Encoder(Bcg729EncoderChannelContextStruct*,
                       const int16_t* inputFrame, uint8_t* bitStream,
                       uint8_t* bitStreamLength);
    // Decode 10 bytes -> 80 int16 PCM samples.
    void bcg729Decoder(Bcg729DecoderChannelContextStruct*,
                       const uint8_t* bitStream, uint8_t bitStreamLength,
                       uint8_t erasureFlag, uint8_t SIDFrameFlag,
                       uint8_t rfc3389PayloadFlag, int16_t* signal);
}
#endif

namespace sip {

/** @brief ICodec implementation backed by libbcg729. */
class G729Codec final : public ICodec {
public:
    /** @brief Construct encoder/decoder contexts when available. */
    G729Codec() {
#ifdef HAVE_BCG729
        enc_ = initBcg729EncoderChannel(0);
        dec_ = initBcg729DecoderChannel();
#endif
    }
    /** @brief Destroy encoder/decoder contexts. */
    ~G729Codec() {
#ifdef HAVE_BCG729
        if (enc_) closeBcg729EncoderChannel(enc_);
        if (dec_) closeBcg729DecoderChannel(dec_);
#endif
    }

    /** @brief Return static payload type for G.729. */
    uint8_t     payloadType()  const override { return 18; }
    /** @brief Return codec name token. */
    const char* name()         const override { return "G729"; }
    /** @brief Return codec clock rate in Hz. */
    uint32_t    clockRate()    const override { return 8000; }
    /** @brief Return number of channels (mono). */
    uint8_t     channels()     const override { return 1; }
    /** @brief Encoded bytes for a 20ms frame. */
    size_t      frameBytes()   const override { return 20; }
    /** @brief Return PCM samples per 20ms frame. */
    size_t      frameSamples() const override { return 160; }

    /** @brief Encode 20ms PCM frame into two 10-byte G.729 blocks. */
    size_t encode(const int16_t* pcm, size_t samples,
                  uint8_t* out, size_t outMax) override {
#ifdef HAVE_BCG729
        if (!enc_ || samples < 160 || outMax < 20) return 0;
        uint8_t frameLen = 0;
        bcg729Encoder(enc_, pcm,      out,    &frameLen);
        if (frameLen != 10) return 0;
        bcg729Encoder(enc_, pcm + 80, out+10, &frameLen);
        if (frameLen != 10) return 0;
        return 20;
#else
        (void)pcm;(void)samples;(void)out;(void)outMax; return 0;
#endif
    }

    /** @brief Decode one or two G.729 blocks into PCM samples. */
    size_t decode(const uint8_t* data, size_t len,
                  int16_t* pcm, size_t maxSamples) override {
#ifdef HAVE_BCG729
        if (!dec_ || maxSamples < 80) return 0;
        size_t out = 0;
        if (len >= 10) {
            bcg729Decoder(dec_, data,    10, 0, 0, 0, pcm);
            out = 80;
        }
        if (len >= 20 && maxSamples >= 160) {
            bcg729Decoder(dec_, data+10, 10, 0, 0, 0, pcm+80);
            out = 160;
        }
        return out;
#else
        (void)data;(void)len;(void)pcm;(void)maxSamples; return 0;
#endif
    }

    /** @brief True when libbcg729 backend is available and initialized. */
    bool available() const override { return valid(); }

    /** @brief True when both encoder and decoder are initialized. */
    bool valid() const {
#ifdef HAVE_BCG729
        return enc_ && dec_;
#else
        return false;
#endif
    }

private:
#ifdef HAVE_BCG729
    /** Encoder context pointer. */
    Bcg729EncoderChannelContextStruct* enc_ = nullptr;
    /** Decoder context pointer. */
    Bcg729DecoderChannelContextStruct* dec_ = nullptr;
#else
    /** Encoder placeholder when library is unavailable. */
    void* enc_ = nullptr;
    /** Decoder placeholder when library is unavailable. */
    void* dec_ = nullptr;
#endif
};

} // namespace sip
