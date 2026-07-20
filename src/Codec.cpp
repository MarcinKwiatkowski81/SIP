// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// Codec.cpp – G.711 implementation + CodecRegistry
#include "Codec.h"
#include <cstdio>
#include <cstring>
#include <cctype>

namespace sip {

// ── G.711 μ-law ──────────────────────────────────────────────────────────────
static const int16_t kUlawDecodeTable[256] = {
    -32124,-31100,-30076,-29052,-28028,-27004,-25980,-24956,
    -23932,-22908,-21884,-20860,-19836,-18812,-17788,-16764,
    -15996,-15484,-14972,-14460,-13948,-13436,-12924,-12412,
    -11900,-11388,-10876,-10364, -9852, -9340, -8828, -8316,
     -7932, -7676, -7420, -7164, -6908, -6652, -6396, -6140,
     -5884, -5628, -5372, -5116, -4860, -4604, -4348, -4092,
     -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004,
     -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
     -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436,
     -1372, -1308, -1244, -1180, -1116, -1052,  -988,  -924,
      -876,  -844,  -812,  -780,  -748,  -716,  -684,  -652,
      -620,  -588,  -556,  -524,  -492,  -460,  -428,  -396,
      -372,  -356,  -340,  -324,  -308,  -292,  -276,  -260,
      -244,  -228,  -212,  -196,  -180,  -164,  -148,  -132,
      -120,  -112,  -104,   -96,   -88,   -80,   -72,   -64,
       -56,   -48,   -40,   -32,   -24,   -16,    -8,     0,
     32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956,
     23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764,
     15996, 15484, 14972, 14460, 13948, 13436, 12924, 12412,
     11900, 11388, 10876, 10364,  9852,  9340,  8828,  8316,
      7932,  7676,  7420,  7164,  6908,  6652,  6396,  6140,
      5884,  5628,  5372,  5116,  4860,  4604,  4348,  4092,
      3900,  3772,  3644,  3516,  3388,  3260,  3132,  3004,
      2876,  2748,  2620,  2492,  2364,  2236,  2108,  1980,
      1884,  1820,  1756,  1692,  1628,  1564,  1500,  1436,
      1372,  1308,  1244,  1180,  1116,  1052,   988,   924,
       876,   844,   812,   780,   748,   716,   684,   652,
       620,   588,   556,   524,   492,   460,   428,   396,
       372,   356,   340,   324,   308,   292,   276,   260,
       244,   228,   212,   196,   180,   164,   148,   132,
       120,   112,   104,    96,    88,    80,    72,    64,
        56,    48,    40,    32,    24,    16,     8,     0
};

uint8_t G711u::encodeSample(int16_t s) {
    int sign = (s < 0) ? 0 : 0x80;
    if (s < 0) s = -s;
    if (s > 32635) s = 32635;
    s += 132;
    int exp = 7;
    for (int mask = 0x4000; !(s & mask); --exp, mask >>= 1) {}
    int mant = (s >> (exp + 3)) & 0x0F;
    return (uint8_t)(~(sign | (exp << 4) | mant));
}
int16_t G711u::decodeSample(uint8_t u) { return kUlawDecodeTable[u]; }
size_t G711u::encode(const int16_t* pcm, size_t n, uint8_t* out, size_t max) {
    if (n > max) n = max;
    for (size_t i=0;i<n;++i) out[i]=encodeSample(pcm[i]);
    return n;
}
size_t G711u::decode(const uint8_t* in, size_t n, int16_t* pcm, size_t max) {
    if (n > max) n = max;
    for (size_t i=0;i<n;++i) pcm[i]=decodeSample(in[i]);
    return n;
}

// ── G.711 A-law ──────────────────────────────────────────────────────────────
uint8_t G711a::encodeSample(int16_t s) {
    int sign = (s >= 0) ? 0x80 : 0;
    if (s < 0) s = ~s;
    if (s > 32767) s = 32767;
    uint8_t exp = 7;
    for (int mask = 0x4000; !(s & mask) && exp > 0; --exp, mask>>=1){}
    uint8_t mant;
    if (exp == 0) mant = (uint8_t)(s >> 1) & 0x0F;
    else          mant = (uint8_t)(s >> (exp)) & 0x0F;
    return (uint8_t)((sign | (exp<<4) | mant) ^ 0x55);
}
int16_t G711a::decodeSample(uint8_t a) {
    a ^= 0x55;
    int sign = a & 0x80;
    int exp  = (a >> 4) & 0x07;
    int mant = a & 0x0F;
    int s = (exp == 0) ? (mant << 1) | 1 : ((mant | 0x10) << exp);
    s <<= 3;
    return (int16_t)(sign ? s : -s);
}
size_t G711a::encode(const int16_t* pcm, size_t n, uint8_t* out, size_t max) {
    if (n > max) n = max;
    for (size_t i=0;i<n;++i) out[i]=encodeSample(pcm[i]);
    return n;
}
size_t G711a::decode(const uint8_t* in, size_t n, int16_t* pcm, size_t max) {
    if (n > max) n = max;
    for (size_t i=0;i<n;++i) pcm[i]=decodeSample(in[i]);
    return n;
}

// ── CodecRegistry ─────────────────────────────────────────────────────────────
CodecRegistry::CodecRegistry() {
    // Built-in non-owned codecs
    codecs_[0]=&g711u_; owned_[0]=false;
    codecs_[1]=&g711a_; owned_[1]=false;
    codecs_[2]=&telEv_; owned_[2]=false;
    count_=3;
}
CodecRegistry::~CodecRegistry() {
    for (size_t i=0;i<count_;++i) if (owned_[i]) delete codecs_[i];
}

bool CodecRegistry::add(ICodec* c) {
    if (!c || count_ >= Cap) return false;
    for (size_t i=0;i<count_;++i)
        if (codecs_[i]->payloadType()==c->payloadType()) return false; // duplicate PT
    codecs_[count_] = c; owned_[count_] = true; ++count_;
    return true;
}

bool CodecRegistry::replace(uint8_t pt, ICodec* newCodec) {
    for (size_t i=0;i<count_;++i) {
        if (codecs_[i]->payloadType()==pt) {
            if (owned_[i]) delete codecs_[i];
            codecs_[i]=newCodec; owned_[i]=true;
            return true;
        }
    }
    return false;
}

bool CodecRegistry::remove(uint8_t pt) {
    for (size_t i=0;i<count_;++i) {
        if (codecs_[i]->payloadType()==pt) {
            if (owned_[i]) delete codecs_[i];
            // compact
            for (size_t j=i;j+1<count_;++j) {
                codecs_[j]=codecs_[j+1]; owned_[j]=owned_[j+1];
            }
            --count_; codecs_[count_]=nullptr; owned_[count_]=false;
            return true;
        }
    }
    return false;
}

ICodec* CodecRegistry::findByPT(uint8_t pt) const {
    for (size_t i=0;i<count_;++i) if (codecs_[i]->payloadType()==pt) return codecs_[i];
    return nullptr;
}
ICodec* CodecRegistry::findByName(const char* n) const {
    for (size_t i=0;i<count_;++i)
        if (strcasecmp(codecs_[i]->name(),n)==0) return codecs_[i];
    return nullptr;
}
void CodecRegistry::printAll() const {
    printf("%-20s %4s %8s %5s %8s %8s %s\n",
           "Name","PT","ClkRate","Ch","FrmBytes","FrmSamp","Status");
    for (size_t i=0;i<count_;++i) {
        ICodec* c=codecs_[i];
     const bool functional = c->available();
        printf("%-20s %4u %8u %5u %8zu %8zu  %s\n",
               c->name(), c->payloadType(), c->clockRate(), c->channels(),
               c->frameBytes(), c->frameSamples(),
               functional ? "OK" : "STUB (no library)");
    }
}

} // namespace sip
