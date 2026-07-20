// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

/**
 * @file Codec.h
 * @brief Audio codec interface and codec registry.
 */
#pragma once
#include <cstdint>
#include <cstddef>

namespace sip {

/** @brief Abstract RTP audio codec contract. */
class ICodec {
public:
    virtual ~ICodec() = default;
    /** @brief RTP payload type. */
    virtual uint8_t     payloadType()  const = 0;
    /** @brief Human-readable codec name. */
    virtual const char* name()         const = 0;
    /** @brief Sampling rate in Hz. */
    virtual uint32_t    clockRate()    const = 0;
    /** @brief Number of channels. */
    virtual uint8_t     channels()     const = 0;
    /** @brief Encoded frame size in bytes. */
    virtual size_t      frameBytes()   const = 0;
    /** @brief PCM sample count per codec frame. */
    virtual size_t      frameSamples() const = 0;
    /** @brief Encode PCM to codec frame bytes. */
    virtual size_t encode(const int16_t* pcm, size_t samples,
                          uint8_t* out, size_t outMax) = 0;
    /** @brief Decode codec frame bytes to PCM samples. */
    virtual size_t decode(const uint8_t* data, size_t len,
                          int16_t* pcm, size_t maxSamples) = 0;
    /** @brief True when codec backend is actually available for use. */
    virtual bool available() const { return true; }
};

/** @brief Built-in G.711 u-law codec (PCMU, PT 0). */
class G711u final : public ICodec {
public:
    uint8_t     payloadType()  const override { return 0; }
    const char* name()         const override { return "PCMU"; }
    uint32_t    clockRate()    const override { return 8000; }
    uint8_t     channels()     const override { return 1; }
    size_t      frameBytes()   const override { return 160; }
    size_t      frameSamples() const override { return 160; }
    size_t encode(const int16_t*, size_t, uint8_t*, size_t) override;
    size_t decode(const uint8_t*, size_t, int16_t*, size_t) override;
    /** @brief Convert one PCM sample to u-law byte. */
    static uint8_t  encodeSample(int16_t linear);
    /** @brief Convert one u-law byte to PCM sample. */
    static int16_t  decodeSample(uint8_t ulaw);
};

/** @brief Built-in G.711 A-law codec (PCMA, PT 8). */
class G711a final : public ICodec {
public:
    uint8_t     payloadType()  const override { return 8; }
    const char* name()         const override { return "PCMA"; }
    uint32_t    clockRate()    const override { return 8000; }
    uint8_t     channels()     const override { return 1; }
    size_t      frameBytes()   const override { return 160; }
    size_t      frameSamples() const override { return 160; }
    size_t encode(const int16_t*, size_t, uint8_t*, size_t) override;
    size_t decode(const uint8_t*, size_t, int16_t*, size_t) override;
    /** @brief Convert one PCM sample to A-law byte. */
    static uint8_t  encodeSample(int16_t linear);
    /** @brief Convert one A-law byte to PCM sample. */
    static int16_t  decodeSample(uint8_t alaw);
};

/** @brief RFC4733 telephone-event pseudo codec (PT 101). */
class TelephoneEvent final : public ICodec {
public:
    uint8_t     payloadType()  const override { return 101; }
    const char* name()         const override { return "telephone-event"; }
    uint32_t    clockRate()    const override { return 8000; }
    uint8_t     channels()     const override { return 1; }
    size_t      frameBytes()   const override { return 4; }
    size_t      frameSamples() const override { return 160; }
    /** @brief DTMF event codec does not encode PCM audio. */
    size_t encode(const int16_t*, size_t, uint8_t*, size_t) override { return 0; }
    /** @brief DTMF event codec does not decode to PCM audio. */
    size_t decode(const uint8_t*, size_t, int16_t*, size_t) override { return 0; }
};

/** @brief Owned registry of active codecs keyed by payload type. */
class CodecRegistry {
public:
    /** Maximum codec entries in registry. */
    static constexpr size_t Cap = 32;   // increased from 16 for extended codec set

    /** @brief Construct registry with built-in baseline codecs. */
    CodecRegistry();
    /** @brief Destroy registry and owned codecs. */
    ~CodecRegistry();

    /** @brief Add codec and transfer ownership to registry. */
    bool add(ICodec* c);

    /** @brief Replace codec for payload type and delete previous instance. */
    bool replace(uint8_t pt, ICodec* newCodec);

    /** @brief Remove codec by payload type. */
    bool remove(uint8_t pt);

    /** @brief Find codec by payload type. */
    ICodec* findByPT(uint8_t pt)     const;
    /** @brief Find codec by name string. */
    ICodec* findByName(const char* n) const;
    /** @brief Return codec at index or nullptr. */
    ICodec* at(size_t i)             const { return i<count_?codecs_[i]:nullptr; }
    /** @brief Number of currently registered codecs. */
    size_t  count()                  const { return count_; }

    /** @brief Print codec summary to stdout. */
    void printAll() const;

private:
    ICodec* codecs_[Cap] = {};
    bool    owned_[Cap]  = {};   // true if registry should delete
    size_t  count_       = 0;

    G711u          g711u_;
    G711a          g711a_;
    TelephoneEvent telEv_;
};

} // namespace sip
