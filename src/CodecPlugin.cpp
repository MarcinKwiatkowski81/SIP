// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// CodecPlugin.cpp – Dynamic codec attachment (dlopen + factory)
#include "CodecPlugin.h"
#include "codecs/SlinCodec.h"
#include "codecs/GsmCodec.h"
#include "codecs/G729Codec.h"
#include "codecs/Codec2Codec.h"
#include "codecs/StubCodec.h"
#include <cstdio>
#include <cstring>
#include <dlfcn.h>

namespace sip {

// ── C ABI shim wrapping a dlopen'd .so codec ─────────────────────────────────
class SoCodec final : public ICodec {
public:
    using FnName    = const char*(*)();
    using FnPt      = uint8_t(*)();
    using FnClk     = uint32_t(*)();
    using FnCh      = uint8_t(*)();
    using FnSzB     = size_t(*)();
    using FnCreate  = void*(*)();
    using FnDestroy = void(*)(void*);
    using FnEncode  = size_t(*)(void*, const int16_t*, size_t, uint8_t*, size_t);
    using FnDecode  = size_t(*)(void*, const uint8_t*, size_t, int16_t*, size_t);

    void*     dl      = nullptr;
    void*     state   = nullptr;
    FnName    fnName  = nullptr;
    FnPt      fnPt    = nullptr;
    FnClk     fnClk   = nullptr;
    FnCh      fnCh    = nullptr;
    FnSzB     fnFrB   = nullptr;
    FnSzB     fnFrS   = nullptr;
    FnDestroy fnDest  = nullptr;
    FnEncode  fnEnc   = nullptr;
    FnDecode  fnDec   = nullptr;

    ~SoCodec() {
        if (state && fnDest) fnDest(state);
        if (dl) dlclose(dl);
    }

    uint8_t     payloadType()  const override { return fnPt  ? fnPt()  : 0;   }
    const char* name()         const override { return fnName? fnName(): "?";  }
    uint32_t    clockRate()    const override { return fnClk ? fnClk() : 8000; }
    uint8_t     channels()     const override { return fnCh  ? fnCh()  : 1;   }
    size_t      frameBytes()   const override { return fnFrB ? fnFrB() : 0;   }
    size_t      frameSamples() const override { return fnFrS ? fnFrS() : 160; }

    size_t encode(const int16_t* pcm, size_t n, uint8_t* out, size_t max) override {
        return (fnEnc && state) ? fnEnc(state, pcm, n, out, max) : 0;
    }
    size_t decode(const uint8_t* in, size_t n, int16_t* pcm, size_t max) override {
        return (fnDec && state) ? fnDec(state, in, n, pcm, max) : 0;
    }
};

// ── CodecPlugin::fromSo ───────────────────────────────────────────────────────
CodecPlugin CodecPlugin::fromSo(const char* soPath) {
    void* dl = dlopen(soPath, RTLD_NOW | RTLD_LOCAL);
    if (!dl) {
        fprintf(stderr, "[CODEC] dlopen(%s): %s\n", soPath, dlerror());
        return CodecPlugin();
    }
#define LOAD(sym, field, type) \
    sc->field = (SoCodec::type)dlsym(dl, sym); \
    if (!sc->field) { fprintf(stderr,"[CODEC] missing symbol '%s' in %s\n", sym, soPath); \
                      dlclose(dl); delete sc; return CodecPlugin(); }

    auto* sc = new SoCodec();
    sc->dl = dl;
    LOAD("sip_codec_name",          fnName, FnName)
    LOAD("sip_codec_pt",            fnPt,   FnPt)
    LOAD("sip_codec_clockrate",     fnClk,  FnClk)
    LOAD("sip_codec_channels",      fnCh,   FnCh)
    LOAD("sip_codec_frame_bytes",   fnFrB,  FnSzB)
    LOAD("sip_codec_frame_samples", fnFrS,  FnSzB)
    LOAD("sip_codec_destroy",       fnDest, FnDestroy)
    LOAD("sip_codec_encode",        fnEnc,  FnEncode)
    LOAD("sip_codec_decode",        fnDec,  FnDecode)
#undef LOAD
    // sip_codec_create is optional (some stateless codecs skip it)
    auto fnCreate = (SoCodec::FnCreate)dlsym(dl, "sip_codec_create");
    if (fnCreate) sc->state = fnCreate();
    printf("[CODEC] Loaded plugin %s  PT=%u  %s\n",
           soPath, sc->fnPt(), sc->fnName());
    return CodecPlugin(sc);
}

// ── CodecPlugin::fromFactory ─────────────────────────────────────────────────
CodecPlugin CodecPlugin::fromFactory(std::function<ICodec*()> factory) {
    ICodec* c = factory();
    if (!c) return CodecPlugin();
    printf("[CODEC] Factory-registered codec %s  PT=%u\n", c->name(), c->payloadType());
    return CodecPlugin(c);
}

// ── Built-in codec builders ───────────────────────────────────────────────────
CodecPlugin CodecPlugin::makeSlin(uint8_t pt)     { return CodecPlugin(new SlinCodec(pt)); }
CodecPlugin CodecPlugin::makeGsm()                { auto* c=new GsmCodec(); return c->valid()?CodecPlugin(c):(delete c,CodecPlugin()); }
CodecPlugin CodecPlugin::makeG729()               { auto* c=new G729Codec(); return c->valid()?CodecPlugin(c):(delete c,CodecPlugin()); }
CodecPlugin CodecPlugin::makeCodec2(int m, uint8_t pt){ auto*c=new Codec2Codec((Codec2Mode)m,pt); return c->valid()?CodecPlugin(c):(delete c,CodecPlugin()); }
CodecPlugin CodecPlugin::makeG7231Stub()          { return CodecPlugin(sip::makeG7231Stub()); }
CodecPlugin CodecPlugin::makeSilkStub(uint8_t pt) { return CodecPlugin(sip::makeSilkStub(pt)); }
CodecPlugin CodecPlugin::makeMelpStub(uint8_t pt) { return CodecPlugin(sip::makeMelpStub(pt)); }
CodecPlugin CodecPlugin::makeMelpeStub(uint8_t pt){ return CodecPlugin(sip::makeMelpeStub(pt));}
CodecPlugin CodecPlugin::makeTwelpStub(uint8_t pt){ return CodecPlugin(sip::makeTwelpStub(pt));}

// ── registerAllCodecs ─────────────────────────────────────────────────────────
void registerAllCodecs(CodecRegistry& reg, bool includeStubs) {
    // G.711 u-law/a-law + telephone-event already in default CodecRegistry ctor.

    // SLIN (L16 8kHz mono, PT 11) – always available
    { auto p=CodecPlugin::makeSlin(); if(p) reg.add(p.release()); }

    // GSM FR (PT 3)
    { auto p=CodecPlugin::makeGsm();
      if(p) { reg.add(p.release()); printf("[CODEC] GSM-FR loaded\n"); }
      else    printf("[CODEC] GSM-FR: HAVE_GSM not set or libgsm missing\n"); }

    // G.729A (PT 18)
    { auto p=CodecPlugin::makeG729();
      if(p) { reg.add(p.release()); printf("[CODEC] G.729A loaded\n"); }
      else    printf("[CODEC] G.729A: HAVE_BCG729 not set or libbcg729 missing\n"); }

    // CODEC2 2400bps (PT 96)
    { auto p=CodecPlugin::makeCodec2(1, 96);
      if(p) { reg.add(p.release()); printf("[CODEC] CODEC2-2400 loaded\n"); }
      else    printf("[CODEC] CODEC2: HAVE_CODEC2 not set or libcodec2 missing\n"); }

    if (!includeStubs) return;

    // Stubs for codecs with no OSS library
    { auto p=CodecPlugin::makeG7231Stub();  if(p) reg.add(p.release()); }
    { auto p=CodecPlugin::makeSilkStub();   if(p) reg.add(p.release()); }
    { auto p=CodecPlugin::makeMelpStub();   if(p) reg.add(p.release()); }
    { auto p=CodecPlugin::makeMelpeStub();  if(p) reg.add(p.release()); }
    { auto p=CodecPlugin::makeTwelpStub();  if(p) reg.add(p.release()); }

    printf("[CODEC] Stubs registered: G.723.1(PT4) SILK(PT97) MELP(PT98) MELPe(PT99) TWELP(PT100)\n");
    printf("[CODEC] Replace stubs via CodecPlugin::fromSo() or fromFactory()\n");
}

// ── Plugin template ───────────────────────────────────────────────────────────
void printCodecPluginTemplate() {
    puts(
R"(/* ── SIP stack codec plugin template ──────────────────────────────────────
 * Compile:  gcc -shared -fPIC -o mycodec.so mycodec.c -lmycodeclib
 * Load:     CodecPlugin p = CodecPlugin::fromSo("./mycodec.so");
 *           if (p) registry.add(p.release());
 * -------------------------------------------------------------------------*/
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Replace these with your codec's real implementation */
#define MY_CODEC_NAME       "MYCODEC"
#define MY_CODEC_PT         97          /* dynamic PT 96–127 */
#define MY_CODEC_CLOCKRATE  8000
#define MY_CODEC_CHANNELS   1
#define MY_CODEC_FRAME_BYTES  20        /* compressed bytes per frame */
#define MY_CODEC_FRAME_SAMPLES 160      /* PCM samples per frame (20ms@8kHz) */

typedef struct { /* your codec state */ int dummy; } MyCodecState;

const char* sip_codec_name()          { return MY_CODEC_NAME; }
uint8_t     sip_codec_pt()            { return MY_CODEC_PT; }
uint32_t    sip_codec_clockrate()     { return MY_CODEC_CLOCKRATE; }
uint8_t     sip_codec_channels()      { return MY_CODEC_CHANNELS; }
size_t      sip_codec_frame_bytes()   { return MY_CODEC_FRAME_BYTES; }
size_t      sip_codec_frame_samples() { return MY_CODEC_FRAME_SAMPLES; }

void* sip_codec_create() {
    MyCodecState* s = calloc(1, sizeof(MyCodecState));
    /* your_codec_init(s); */
    return s;
}
void sip_codec_destroy(void* state) {
    /* your_codec_free((MyCodecState*)state); */
    free(state);
}
size_t sip_codec_encode(void* state,
                        const int16_t* pcm, size_t samples,
                        uint8_t* out, size_t outMax) {
    if (samples < MY_CODEC_FRAME_SAMPLES || outMax < MY_CODEC_FRAME_BYTES) return 0;
    /* your_codec_encode((MyCodecState*)state, pcm, out); */
    memset(out, 0, MY_CODEC_FRAME_BYTES); /* placeholder */
    return MY_CODEC_FRAME_BYTES;
}
size_t sip_codec_decode(void* state,
                        const uint8_t* data, size_t len,
                        int16_t* pcm, size_t maxSamples) {
    if (len < MY_CODEC_FRAME_BYTES || maxSamples < MY_CODEC_FRAME_SAMPLES) return 0;
    /* your_codec_decode((MyCodecState*)state, data, pcm); */
    memset(pcm, 0, MY_CODEC_FRAME_SAMPLES * 2); /* placeholder */
    return MY_CODEC_FRAME_SAMPLES;
}
)");
}

} // namespace sip
