// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file SlinCodec.h
 * @brief Signed linear PCM codec wrapper.
 */
#pragma once
#include "Codec.h"
namespace sip {

/** @brief ICodec implementation for L16/8000/1. */
class SlinCodec final : public ICodec {
public:
    /** @brief Construct with configurable payload type. */
    explicit SlinCodec(uint8_t pt = 11) : pt_(pt) {}

    /** @brief Return configured RTP payload type. */
    uint8_t     payloadType()  const override { return pt_; }
    /** @brief Return codec name token. */
    const char* name()         const override { return "L16"; }
    /** @brief Return codec clock rate in Hz. */
    uint32_t    clockRate()    const override { return 8000; }
    /** @brief Return number of channels (mono). */
    uint8_t     channels()     const override { return 1; }
    /** @brief Return encoded bytes for one 20ms frame. */
    size_t      frameBytes()   const override { return 320; } // 160 * 2
    /** @brief Return PCM samples for one frame. */
    size_t      frameSamples() const override { return 160; }

    /** @brief Encode host-endian PCM to network-endian L16 bytes. */
    size_t encode(const int16_t* pcm, size_t samples,
                  uint8_t* out, size_t outMax) override {
        size_t bytes = samples * 2;
        if (bytes > outMax) bytes = outMax & ~1u;
        for (size_t i = 0; i < bytes/2; ++i) {
            int16_t s = pcm[i];
            out[i*2  ] = (uint8_t)(s >> 8);
            out[i*2+1] = (uint8_t)(s);
        }
        return bytes;
    }

    /** @brief Decode network-endian L16 bytes to host-endian PCM. */
    size_t decode(const uint8_t* data, size_t len,
                  int16_t* pcm, size_t maxSamples) override {
        size_t samples = len / 2;
        if (samples > maxSamples) samples = maxSamples;
        for (size_t i = 0; i < samples; ++i)
            pcm[i] = (int16_t)((data[i*2] << 8) | data[i*2+1]);
        return samples;
    }

private:
    /** Configured RTP payload type. */
    uint8_t pt_;
};

} // namespace sip
