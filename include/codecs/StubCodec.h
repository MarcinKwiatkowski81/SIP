// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// StubCodec.h – Placeholder ICodec for codecs with no OSS implementation.
//
// A StubCodec:
//   - Registers correctly in CodecRegistry so SDP offer/answer includes
//     the codec in the capability list.
//   - encode() always returns 0 (silence).
//   - decode() always returns silence frames (zeros).
//   - valid() returns false.
//
// Replace a stub by calling CodecRegistry::replace(pt, realCodec) after
// loading the real implementation via CodecPlugin::fromSo() or fromFactory().
//
// Codecs implemented as stubs here:
//   G.723.1  – PT  4 –  6.3/5.3 kbps, 30ms frames
//   SILK     – PT 97 –  variable bitrate 6–40 kbps  (Skype / RFC 7587)
//   MELP     – PT 98 –  2400 bps, 22.5ms frames (MIL-STD-3005/STANAG 4591)
//   MELPe    – PT 99 –  600/1200/2400 bps          (STANAG 4591)
//   TWELP    – PT 100–  600 bps (Wideband LPC, NATO STANAG 4198 family)
//
// Real open-source / commercial implementations:
//   G.723.1 : Intel IPP, bcg7231 (not publicly available)
//             Or load an Asterisk-compatible .so plugin
//   SILK    : https://github.com/gaozehua/SILKCodec (original Skype SDK)
//             Or use libopus which subsumes SILK via Opus hybrid mode
//   MELP    : US DoD reference code (MELP_STANAG4591.zip from DISA)
//             Or commercial impl from Vocal Technologies / DVSI
//   MELPe   : Same sources as MELP above
//   TWELP   : SPAWAR / NATO reference implementation
//             Or commercial impl; contact codec vendor
#pragma once
#include "Codec.h"
#include <cstring>
namespace sip {

/** @brief Placeholder codec implementation that advertises capability but encodes silence. */
class StubCodec final : public ICodec {
public:
    /** @brief Construct placeholder codec descriptor. */
    StubCodec(const char* name, uint8_t pt, uint32_t clockRate,
              size_t frameBytes, size_t frameSamples)
        : pt_(pt), clockRate_(clockRate),
          frameBytes_(frameBytes), frameSamples_(frameSamples) {
        // copy name safely
        size_t l = strlen(name); if(l>=sizeof(name_)-1) l=sizeof(name_)-1;
        memcpy(name_, name, l); name_[l]=0;
    }

    /** @brief Return advertised RTP payload type. */
    uint8_t     payloadType()  const override { return pt_; }
    /** @brief Return codec display name. */
    const char* name()         const override { return name_; }
    /** @brief Return advertised clock rate. */
    uint32_t    clockRate()    const override { return clockRate_; }
    /** @brief Return channel count (always mono for stubs). */
    uint8_t     channels()     const override { return 1; }
    /** @brief Return nominal encoded frame size in bytes. */
    size_t      frameBytes()   const override { return frameBytes_; }
    /** @brief Return nominal PCM sample count per frame. */
    size_t      frameSamples() const override { return frameSamples_; }

    /** @brief Stub encoder produces no payload. */
    size_t encode(const int16_t*, size_t, uint8_t*, size_t) override { return 0; }
    /** @brief Stub decoder returns silence frame. */
    size_t decode(const uint8_t*, size_t,
                  int16_t* pcm, size_t maxSamples) override {
        // Comfort noise (silence) so the call doesn't crash
        size_t n = (maxSamples < frameSamples_) ? maxSamples : frameSamples_;
        memset(pcm, 0, n * 2);
        return n;
    }
    /** @brief Stub implementations are placeholders, not functional codecs. */
    bool available() const override { return false; }
    /** @brief Always false for stub codecs. */
    bool valid() const { return false; }

private:
    /** Codec name token returned by name(). */
    char     name_[32]   = {};
    /** RTP payload type number. */
    uint8_t  pt_;
    /** Clock rate in Hz. */
    uint32_t clockRate_;
    /** Nominal encoded frame size in bytes. */
    size_t   frameBytes_;
    /** Nominal decoded PCM frame samples. */
    size_t   frameSamples_;
};

// ── Pre-configured stubs ──────────────────────────────────────────────────────

// G.723.1 – 30ms / 240 samples per frame; 6.3kbps → 24 bytes, 5.3kbps → 20 bytes
// We announce 6.3kbps (24 bytes) in SDP.
inline StubCodec* makeG7231Stub() {
    return new StubCodec("G7231", 4, 8000, 24, 240);
}

// SILK wideband – 20ms frames at 16kHz (320 samples), variable bytes.
// Fallback announcement: 20ms @ 8kHz (160 samples), 32 bytes (12.8kbps).
inline StubCodec* makeSilkStub(uint8_t pt = 97) {
    return new StubCodec("SILK", pt, 8000, 32, 160);
}

// MELP 2400 bps – 22.5ms/180 samples per frame, 54 bits = 7 bytes (padded to 8)
inline StubCodec* makeMelpStub(uint8_t pt = 98) {
    return new StubCodec("MELP", pt, 8000, 8, 180);
}

// MELPe – same frame structure, announced at 2400bps default
inline StubCodec* makeMelpeStub(uint8_t pt = 99) {
    return new StubCodec("MELPe", pt, 8000, 8, 180);
}

// TWELP (Wideband LPC ~600bps variant, 30ms frames)
inline StubCodec* makeTwelpStub(uint8_t pt = 100) {
    return new StubCodec("TWELP", pt, 8000, 4, 240);
}

} // namespace sip
