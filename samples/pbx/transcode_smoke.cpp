// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

#include "Codec.h"
#include "CodecPlugin.h"
#include "Rtp.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace sip;

namespace {

bool pcmEnergyOk(const int16_t* s, size_t n) {
    long long sumAbs = 0;
    for (size_t i = 0; i < n; ++i) {
        sumAbs += std::llabs((long long)s[i]);
    }
    return sumAbs > 0;
}

void generateSine20ms(int16_t* out, size_t n, int hz = 440, int sr = 8000) {
    const double amp = 11000.0;
    for (size_t i = 0; i < n; ++i) {
        const double t = (double)i / (double)sr;
        out[i] = (int16_t)(amp * std::sin(2.0 * M_PI * (double)hz * t));
    }
}

bool runBridge(ICodec* a, ICodec* b) {
    if (!a || !b) return false;

    const size_t samples = a->frameSamples();
    std::vector<int16_t> pcmIn(samples, 0);
    generateSine20ms(pcmIn.data(), samples);

    std::vector<uint8_t> aEnc(2048, 0);
    std::vector<int16_t> aDec(4096, 0);
    std::vector<uint8_t> bEnc(2048, 0);
    std::vector<int16_t> bDec(4096, 0);

    const size_t aEncLen = a->encode(pcmIn.data(), samples, aEnc.data(), aEnc.size());
    if (!aEncLen) return false;

    const size_t aDecSamples = a->decode(aEnc.data(), aEncLen, aDec.data(), aDec.size());
    if (!aDecSamples) return false;

    const size_t bEncLen = b->encode(aDec.data(), aDecSamples, bEnc.data(), bEnc.size());
    if (!bEncLen) return false;

    const size_t bDecSamples = b->decode(bEnc.data(), bEncLen, bDec.data(), bDec.size());
    if (!bDecSamples) return false;

    return pcmEnergyOk(bDec.data(), bDecSamples);
}

bool transcodeRtpPacketLocal(const uint8_t* in, size_t inLen,
                             uint8_t* out, size_t outCap, size_t* outLen,
                             uint8_t dstPt, ICodec* srcCodec, ICodec* dstCodec) {
    if (!in || !out || !outLen || inLen < sizeof(RtpHdr) || outCap < inLen) {
        return false;
    }

    const RtpHdr* h = (const RtpHdr*)in;
    const size_t csrcBytes = (size_t)h->csrcCount() * 4U;
    const size_t hdrLen = sizeof(RtpHdr) + csrcBytes;
    if (h->version() != 2 || hdrLen > inLen || hdrLen > outCap) {
        return false;
    }

    const uint8_t inPt = h->pt();
    const uint8_t* payload = in + hdrLen;
    const size_t payLen = inLen - hdrLen;

    if (inPt == 101 || !srcCodec || !dstCodec || srcCodec == dstCodec) {
        memcpy(out, in, inLen);
        out[1] = (uint8_t)((out[1] & 0x80) | (dstPt & 0x7F));
        *outLen = inLen;
        return true;
    }

    int16_t pcm[2048];
    const size_t samples = srcCodec->decode(payload, payLen, pcm, sizeof(pcm) / sizeof(pcm[0]));
    if (!samples) return false;

    uint8_t enc[2048];
    const size_t encLen = dstCodec->encode(pcm, samples, enc, sizeof(enc));
    if (!encLen || hdrLen + encLen > outCap) return false;

    memcpy(out, in, hdrLen);
    out[1] = (uint8_t)((out[1] & 0x80) | (dstPt & 0x7F));
    memcpy(out + hdrLen, enc, encLen);
    *outLen = hdrLen + encLen;
    return true;
}

bool runRtpPath(ICodec* src, ICodec* dst) {
    if (!src || !dst) return false;

    const size_t frame = src->frameSamples();
    std::vector<int16_t> pcm(frame, 0);
    generateSine20ms(pcm.data(), frame);

    std::vector<uint8_t> enc(2048, 0);
    const size_t encLen = src->encode(pcm.data(), frame, enc.data(), enc.size());
    if (!encLen) return false;

    std::vector<uint8_t> inPkt(sizeof(RtpHdr) + encLen, 0);
    RtpHdr* h = (RtpHdr*)inPkt.data();
    h->init(src->payloadType(), true, 31337, 424242, 0xabcdef01u);
    memcpy(inPkt.data() + sizeof(RtpHdr), enc.data(), encLen);

    std::vector<uint8_t> outPkt(4096, 0);
    size_t outLen = 0;
    if (!transcodeRtpPacketLocal(inPkt.data(), inPkt.size(), outPkt.data(), outPkt.size(), &outLen,
                                 dst->payloadType(), src, dst)) {
        return false;
    }

    if (outLen < sizeof(RtpHdr)) return false;
    const RtpHdr* ho = (const RtpHdr*)outPkt.data();
    if (ho->pt() != dst->payloadType()) return false;
    if (ho->seqH() != h->seqH() || ho->tsH() != h->tsH()) return false;

    const uint8_t* outPay = outPkt.data() + sizeof(RtpHdr);
    const size_t outPayLen = outLen - sizeof(RtpHdr);
    int16_t outPcm[4096] = {0};
    const size_t outSamples = dst->decode(outPay, outPayLen, outPcm, sizeof(outPcm) / sizeof(outPcm[0]));
    if (!outSamples) return false;
    return pcmEnergyOk(outPcm, outSamples);
}

bool runRtpStreamPath(ICodec* src, ICodec* dst, int frames, int lossPercent) {
    if (!src || !dst || frames <= 0) return false;
    if (lossPercent < 0 || lossPercent > 90) return false;

    const size_t frameSamples = src->frameSamples();
    const uint32_t tsStep = (uint32_t)((src->clockRate() * 20U) / 1000U);
    if (tsStep == 0) return false;

    int success = 0;
    int dropped = 0;
    int simulatedDrops = 0;
    uint16_t prevSeq = 0;
    uint32_t prevTs = 0;
    bool first = true;

    const int lossStep = (lossPercent > 0) ? (100 / lossPercent) : 0;
    for (int i = 0; i < frames; ++i) {
        if (lossStep > 0 && i > 0 && (i % lossStep) == 0) {
            ++simulatedDrops;
            continue;
        }

        std::vector<int16_t> pcm(frameSamples, 0);
        const int tone = 300 + (i % 5) * 80;
        generateSine20ms(pcm.data(), frameSamples, tone, (int)src->clockRate());

        std::vector<uint8_t> enc(2048, 0);
        const size_t encLen = src->encode(pcm.data(), frameSamples, enc.data(), enc.size());
        if (!encLen) {
            ++dropped;
            continue;
        }

        std::vector<uint8_t> inPkt(sizeof(RtpHdr) + encLen, 0);
        RtpHdr* h = (RtpHdr*)inPkt.data();
        const uint16_t seq = (uint16_t)(1000 + i);
        const uint32_t ts = 48000 + (uint32_t)i * tsStep;
        h->init(src->payloadType(), false, seq, ts, 0x01020304u);
        memcpy(inPkt.data() + sizeof(RtpHdr), enc.data(), encLen);

        std::vector<uint8_t> outPkt(4096, 0);
        size_t outLen = 0;
        if (!transcodeRtpPacketLocal(inPkt.data(), inPkt.size(),
                                     outPkt.data(), outPkt.size(), &outLen,
                                     dst->payloadType(), src, dst)) {
            ++dropped;
            continue;
        }

        if (outLen < sizeof(RtpHdr)) {
            ++dropped;
            continue;
        }

        const RtpHdr* ho = (const RtpHdr*)outPkt.data();
        if (ho->pt() != dst->payloadType()) {
            ++dropped;
            continue;
        }

        if (!first) {
            const uint16_t deltaSeq = (uint16_t)(ho->seqH() - prevSeq);
            const uint32_t deltaTs = (uint32_t)(ho->tsH() - prevTs);
            if (deltaSeq == 0) {
                ++dropped;
                continue;
            }
            const uint32_t expectedDeltaTs = (uint32_t)deltaSeq * tsStep;
            if (deltaTs != expectedDeltaTs) {
                ++dropped;
                continue;
            }
        }

        const uint8_t* outPay = outPkt.data() + sizeof(RtpHdr);
        const size_t outPayLen = outLen - sizeof(RtpHdr);
        int16_t outPcm[4096] = {0};
        const size_t outSamples = dst->decode(outPay, outPayLen,
                                              outPcm, sizeof(outPcm) / sizeof(outPcm[0]));
        if (!outSamples || !pcmEnergyOk(outPcm, outSamples)) {
            ++dropped;
            continue;
        }

        prevSeq = ho->seqH();
        prevTs = ho->tsH();
        first = false;
        ++success;
    }

    const int expectedDropBudget = simulatedDrops + ((frames + 49) / 50);
    std::printf("[SMOKE] stream frames=%d success=%d dropped=%d simulated=%d allowed=%d\n",
                frames, success, dropped, simulatedDrops, expectedDropBudget);
    return success > 0 && dropped <= expectedDropBudget;
}

void usage(const char* prog) {
    std::printf(
        "Usage: %s [options]\n"
        "  -g <codec.so>     Load codec plugin (repeatable)\n"
        "  -a <codec-name>   Left codec name (default: PCMU)\n"
        "  -b <codec-name>   Right codec name (default: PCMA)\n"
        "  --rtp-path        Validate RTP header + payload remap path\n"
        "  --stream <n>      Validate n RTP frames progression path\n"
        "  --simulate-loss <percent>  Simulate stream packet drops (0-90)\n",
        prog);
}

} // namespace

int main(int argc, char** argv) {
    std::vector<const char*> plugins;
    const char* leftName = "PCMU";
    const char* rightName = "PCMA";
    bool rtpPath = false;
    int streamFrames = 0;
    int simulateLossPercent = 0;

    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "-g") && i + 1 < argc) {
            plugins.push_back(argv[++i]);
        } else if (!std::strcmp(argv[i], "-a") && i + 1 < argc) {
            leftName = argv[++i];
        } else if (!std::strcmp(argv[i], "-b") && i + 1 < argc) {
            rightName = argv[++i];
        } else if (!std::strcmp(argv[i], "--rtp-path")) {
            rtpPath = true;
        } else if (!std::strcmp(argv[i], "--stream") && i + 1 < argc) {
            streamFrames = std::atoi(argv[++i]);
            if (streamFrames < 1) {
                std::fprintf(stderr, "[SMOKE] invalid --stream value\n");
                return 1;
            }
        } else if (!std::strcmp(argv[i], "--simulate-loss") && i + 1 < argc) {
            simulateLossPercent = std::atoi(argv[++i]);
            if (simulateLossPercent < 0 || simulateLossPercent > 90) {
                std::fprintf(stderr, "[SMOKE] invalid --simulate-loss value (0-90)\n");
                return 1;
            }
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    CodecRegistry reg;
    registerAllCodecs(reg, false);

    for (const char* soPath : plugins) {
        CodecPlugin p = CodecPlugin::fromSo(soPath);
        if (!p) {
            std::fprintf(stderr, "[SMOKE] failed to load plugin: %s\n", soPath);
            return 2;
        }
        ICodec* c = p.release();
        if (!reg.add(c)) {
            std::fprintf(stderr, "[SMOKE] plugin rejected by registry: %s\n", soPath);
            delete c;
            return 3;
        }
    }

    ICodec* a = reg.findByName(leftName);
    ICodec* b = reg.findByName(rightName);
    if (!a || !b) {
        std::fprintf(stderr, "[SMOKE] codec not found: %s or %s\n", leftName, rightName);
        reg.printAll();
        return 4;
    }

    bool okAB = false;
    bool okBA = false;
    const char* mode = "codec-only";
    if (streamFrames > 0) {
        mode = "rtp-stream";
        okAB = runRtpStreamPath(a, b, streamFrames, simulateLossPercent);
        okBA = runRtpStreamPath(b, a, streamFrames, simulateLossPercent);
    } else if (rtpPath) {
        mode = "rtp-path";
        okAB = runRtpPath(a, b);
        okBA = runRtpPath(b, a);
    } else {
        okAB = runBridge(a, b);
        okBA = runBridge(b, a);
    }

    std::printf("[SMOKE] mode=%s\n", mode);
    std::printf("[SMOKE] %s -> %s : %s\n", a->name(), b->name(), okAB ? "OK" : "FAIL");
    std::printf("[SMOKE] %s -> %s : %s\n", b->name(), a->name(), okBA ? "OK" : "FAIL");

    return (okAB && okBA) ? 0 : 5;
}
