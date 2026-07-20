// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file GsmCodec.h
 * @brief GSM Full-Rate codec wrapper.
 */
#pragma once
#include "Codec.h"
#ifdef HAVE_GSM
extern "C" {
    typedef struct gsm_state *gsm;
    gsm    gsm_create(void);
    void   gsm_destroy(gsm);
    int    gsm_encode(gsm, short *src, unsigned char *dst);
    int    gsm_decode(gsm, unsigned char *src, short *dst);
}
#endif

namespace sip {

/** @brief ICodec implementation backed by libgsm. */
class GsmCodec final : public ICodec {
public:
        /** @brief Construct encoder/decoder state when available. */
    GsmCodec() {
#ifdef HAVE_GSM
        enc_ = gsm_create();
        dec_ = gsm_create();
#endif
    }
        /** @brief Destroy encoder/decoder state. */
    ~GsmCodec() {
#ifdef HAVE_GSM
        if (enc_) gsm_destroy((gsm)enc_);
        if (dec_) gsm_destroy((gsm)dec_);
#endif
    }

    /** @brief Return static payload type for GSM-FR. */
    uint8_t     payloadType()  const override { return 3; }
    /** @brief Return codec name token. */
    const char* name()         const override { return "GSM"; }
    /** @brief Return codec clock rate in Hz. */
    uint32_t    clockRate()    const override { return 8000; }
    /** @brief Return number of channels (mono). */
    uint8_t     channels()     const override { return 1; }
    /** @brief Return encoded GSM frame size in bytes. */
    size_t      frameBytes()   const override { return 33; }
    /** @brief Return PCM samples per frame. */
    size_t      frameSamples() const override { return 160; }

        /** @brief Encode one GSM frame from PCM input. */
    size_t encode(const int16_t* pcm, size_t samples,
                  uint8_t* out, size_t outMax) override {
#ifdef HAVE_GSM
        if (!enc_ || samples < 160 || outMax < 33) return 0;
        gsm_encode((gsm)enc_, (short*)pcm, (unsigned char*)out);
        return 33;
#else
        (void)pcm; (void)samples; (void)out; (void)outMax; return 0;
#endif
    }
        /** @brief Decode one GSM frame to PCM output. */
    size_t decode(const uint8_t* data, size_t len,
                  int16_t* pcm, size_t maxSamples) override {
#ifdef HAVE_GSM
        if (!dec_ || len < 33 || maxSamples < 160) return 0;
        if (gsm_decode((gsm)dec_, (unsigned char*)data, (short*)pcm) < 0) return 0;
        return 160;
#else
        (void)data; (void)len; (void)pcm; (void)maxSamples; return 0;
#endif
    }

    /** @brief True when libgsm backend is available and initialized. */
    bool available() const override { return valid(); }

        /** @brief True when both GSM contexts are initialized. */
    bool valid() const {
#ifdef HAVE_GSM
        return enc_ && dec_;
#else
        return false;
#endif
    }

private:
        /** Encoder context handle (opaque). */
    void* enc_ = nullptr;
        /** Decoder context handle (opaque). */
    void* dec_ = nullptr;
};

} // namespace sip
