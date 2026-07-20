// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file Codec2Codec.h
 * @brief CODEC2 codec wrapper.
 */
#pragma once
#include "Codec.h"
#ifdef HAVE_CODEC2
extern "C" {
    struct CODEC2; // opaque
    struct CODEC2* codec2_create(int mode);
    void           codec2_destroy(struct CODEC2*);
    void           codec2_encode(struct CODEC2*, unsigned char* bits, short* speech_in);
    void           codec2_decode(struct CODEC2*, short* speech_out, const unsigned char* bits);
    int            codec2_samples_per_frame(struct CODEC2*);
    int            codec2_bits_per_frame(struct CODEC2*);
}
#endif

namespace sip {

/** @brief Supported CODEC2 bit-rate modes. */
enum class Codec2Mode : int {
    BPS_3200 = 0,
    BPS_2400 = 1,
    BPS_1600 = 2,
    BPS_1400 = 3,
    BPS_1300 = 4,
    BPS_1200 = 5,
};

/** @brief ICodec implementation backed by libcodec2. */
class Codec2Codec final : public ICodec {
public:
    /** @brief Construct CODEC2 codec with mode and payload type. */
    Codec2Codec(Codec2Mode mode = Codec2Mode::BPS_2400, uint8_t pt = 96)
        : mode_(mode), pt_(pt) {
#ifdef HAVE_CODEC2
        ctx_ = codec2_create((int)mode);
        if (ctx_) {
            sampPerFrame_ = (size_t)codec2_samples_per_frame(ctx_);
            bitsPerFrame_ = (size_t)codec2_bits_per_frame(ctx_);
            bytesPerFrame_= (bitsPerFrame_ + 7) / 8;
        }
#endif
    }
    /** @brief Destroy codec context. */
    ~Codec2Codec() {
#ifdef HAVE_CODEC2
        if (ctx_) codec2_destroy(ctx_);
#endif
    }

    /** @brief Return RTP payload type. */
    uint8_t     payloadType()  const override { return pt_; }
    /** @brief Return codec name token. */
    const char* name()         const override { return "CODEC2"; }
    /** @brief Return codec clock rate. */
    uint32_t    clockRate()    const override { return 8000; }
    /** @brief Return number of channels (mono). */
    uint8_t     channels()     const override { return 1; }
    /** @brief Return encoded frame size in bytes. */
    size_t      frameBytes()   const override { return bytesPerFrame_; }
    /** @brief Return PCM samples per frame. */
    size_t      frameSamples() const override { return sampPerFrame_; }

    /** @brief Encode one PCM frame into CODEC2 payload bytes. */
    size_t encode(const int16_t* pcm, size_t samples,
                  uint8_t* out, size_t outMax) override {
#ifdef HAVE_CODEC2
        if (!ctx_ || samples < sampPerFrame_ || outMax < bytesPerFrame_) return 0;
        codec2_encode(ctx_, out, (short*)pcm);
        return bytesPerFrame_;
#else
        (void)pcm;(void)samples;(void)out;(void)outMax; return 0;
#endif
    }
    /** @brief Decode CODEC2 payload bytes into PCM frame samples. */
    size_t decode(const uint8_t* data, size_t len,
                  int16_t* pcm, size_t maxSamples) override {
#ifdef HAVE_CODEC2
        if (!ctx_ || len < bytesPerFrame_ || maxSamples < sampPerFrame_) return 0;
        codec2_decode(ctx_, (short*)pcm, data);
        return sampPerFrame_;
#else
        (void)data;(void)len;(void)pcm;(void)maxSamples; return 0;
#endif
    }

    /** @brief True when libcodec2 backend is available and initialized. */
    bool available() const override { return valid(); }

    /** @brief True when codec backend context is available. */
    bool        valid() const { return ctx_ != nullptr; }
    /** @brief Configured CODEC2 mode. */
    Codec2Mode  mode()  const { return mode_; }
    /** @brief Encoded bits per frame for current mode. */
    size_t      bitsPerFrame() const { return bitsPerFrame_; }

private:
    Codec2Mode  mode_;
    uint8_t     pt_;
#ifdef HAVE_CODEC2
    struct CODEC2* ctx_ = nullptr;
#else
    void* ctx_ = nullptr;
#endif
    size_t sampPerFrame_  = 160;
    size_t bitsPerFrame_  = 48;
    size_t bytesPerFrame_ = 6;
};

} // namespace sip
