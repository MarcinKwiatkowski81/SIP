// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// WavFile.h – Minimal PCM WAV reader/writer (8 kHz, mono, 16-bit LE)
//
// Reader:  WavReader  – streams 160-sample (20 ms) frames from a .wav file.
//          Supports 8 kHz mono PCM; resamples 16/22/44/48 kHz down to 8 kHz
//          using a simple decimation (good enough for telephony demos).
//
// Writer:  WavWriter  – collects int16 PCM and writes a standard .wav file
//          on close().  Thread-safe: lock-free ring buffer fed from the RTP
//          receive thread; flushed by the main thread.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <atomic>
#include <string>

// ── RIFF/WAV structures ────────────────────────────────────────────────────────
#pragma pack(push,1)
struct WavHdr {
    char     riff[4];        // "RIFF"
    uint32_t chunkSize;
    char     wave[4];        // "WAVE"
    char     fmt[4];         // "fmt "
    uint32_t fmtSize;        // 16
    uint16_t audioFmt;       // 1 = PCM
    uint16_t channels;
    uint32_t sampleRate;
    uint32_t byteRate;
    uint16_t blockAlign;
    uint16_t bitsPerSample;
    char     data[4];        // "data"
    uint32_t dataSize;
};
#pragma pack(pop)

// ─────────────────────────────────────────────────────────────────────────────
// WavReader
// ─────────────────────────────────────────────────────────────────────────────
class WavReader {
public:
    static constexpr size_t FRAME = 160;   // 20 ms @ 8 kHz

    WavReader() = default;
    ~WavReader() { close(); }

    bool open(const char* path) {
        close();
        fp_ = fopen(path, "rb");
        if (!fp_) { fprintf(stderr, "[WAV] cannot open '%s'\n", path); return false; }

        WavHdr hdr;
        if (fread(&hdr, 1, sizeof hdr, fp_) < sizeof hdr) { close(); return false; }
        if (memcmp(hdr.riff,"RIFF",4)||memcmp(hdr.wave,"WAVE",4)) {
            fprintf(stderr,"[WAV] not a RIFF/WAVE file\n"); close(); return false;
        }
        if (hdr.audioFmt != 1) {
            fprintf(stderr,"[WAV] only PCM (fmt=1) supported, got %u\n",hdr.audioFmt);
            close(); return false;
        }
        if (hdr.bitsPerSample != 16) {
            fprintf(stderr,"[WAV] only 16-bit supported, got %u\n",hdr.bitsPerSample);
            close(); return false;
        }
        srcRate_  = hdr.sampleRate;
        channels_ = hdr.channels;
        dataLeft_ = hdr.dataSize;
        // Compute integer decimation ratio  (e.g. 48000/8000 = 6)
        ratio_    = (srcRate_ + 7999) / 8000;   // ceiling → never skip target
        if (ratio_ < 1) ratio_ = 1;
        printf("[WAV] '%s'  %u Hz  %u ch  %u bytes  ratio→8kHz: %u\n",
               path, srcRate_, channels_, hdr.dataSize, ratio_);
        return true;
    }

    void close() { if (fp_) { fclose(fp_); fp_=nullptr; } dataLeft_=0; done_=false; }
    bool done()  const { return done_; }

    // Fill 'out' with exactly FRAME (160) samples at 8 kHz mono.
    // Returns false when file exhausted (out is zeroed = silence).
    bool nextFrame(int16_t out[FRAME]) {
        memset(out, 0, FRAME * sizeof(int16_t));
        if (done_ || !fp_) { done_=true; return false; }

        size_t produced = 0;
        while (produced < FRAME) {
            // Read one source sample (all channels, then pick first)
            int16_t src[8] = {};
            size_t bytes = (size_t)channels_ * 2;
            if (dataLeft_ < bytes) { done_=true; break; }
            if (fread(src, 2, channels_, fp_) != channels_) { done_=true; break; }
            dataLeft_ -= bytes;
            // Down-mix to mono (average channels)
            int32_t mono = 0;
            for (uint16_t c=0; c<channels_; ++c) mono += src[c];
            mono /= channels_;
            // Decimation: only emit one output sample per ratio_ input samples
            if (++srcPhase_ >= ratio_) {
                srcPhase_ = 0;
                out[produced++] = (int16_t)mono;
            }
        }
        return !done_;
    }

    // Rewind to beginning of data
    void rewind() {
        if (!fp_) return;
        fseek(fp_, (long)sizeof(WavHdr), SEEK_SET);
        dataLeft_ = 0;  // unknown without re-reading header — reload instead
        done_ = false;
        fclose(fp_);
        fp_ = nullptr;
        // Caller must re-open; or better yet just reopen
    }

private:
    FILE*    fp_       = nullptr;
    uint32_t srcRate_  = 8000;
    uint16_t channels_ = 1;
    uint32_t dataLeft_ = 0;
    uint32_t ratio_    = 1;
    uint32_t srcPhase_ = 0;
    bool     done_     = false;
};

// ─────────────────────────────────────────────────────────────────────────────
// WavWriter  – lock-free ring buffer; safe to call push() from any thread
// ─────────────────────────────────────────────────────────────────────────────
class WavWriter {
public:
    static constexpr size_t RING = 64 * 1024;  // ~8 s at 8 kHz

    WavWriter() { ring_.resize(RING, 0); }
    ~WavWriter() { /* call save() before destruction */ }

    void push(const int16_t* pcm, size_t n) {
        for (size_t i=0; i<n; ++i) {
            size_t w = write_.load(std::memory_order_relaxed);
            size_t nw = (w + 1) % RING;
            if (nw == read_.load(std::memory_order_acquire)) return; // full
            ring_[w] = pcm[i];
            write_.store(nw, std::memory_order_release);
        }
    }

    // Drain ring buffer into local vector (call from main thread periodically)
    void drain() {
        while (true) {
            size_t r = read_.load(std::memory_order_relaxed);
            size_t w = write_.load(std::memory_order_acquire);
            if (r == w) break;
            buf_.push_back(ring_[r]);
            read_.store((r+1) % RING, std::memory_order_release);
        }
    }

    // Save PCM as 8-kHz mono 16-bit WAV. Returns true on success.
    bool save(const char* path) {
        drain();
        FILE* f = fopen(path, "wb");
        if (!f) { fprintf(stderr,"[WAV] cannot write '%s'\n",path); return false; }
        WavHdr hdr;
        memcpy(hdr.riff, "RIFF", 4);
        memcpy(hdr.wave, "WAVE", 4);
        memcpy(hdr.fmt,  "fmt ", 4);
        memcpy(hdr.data, "data", 4);
        hdr.fmtSize      = 16;
        hdr.audioFmt     = 1;
        hdr.channels     = 1;
        hdr.sampleRate   = 8000;
        hdr.bitsPerSample= 16;
        hdr.byteRate     = 8000 * 2;
        hdr.blockAlign   = 2;
        uint32_t dataSz  = (uint32_t)(buf_.size() * 2);
        hdr.dataSize     = dataSz;
        hdr.chunkSize    = 36 + dataSz;
        fwrite(&hdr, 1, sizeof hdr, f);
        fwrite(buf_.data(), 2, buf_.size(), f);
        fclose(f);
        double secs = (double)buf_.size() / 8000.0;
        printf("[WAV] saved '%s'  %.2f s  (%zu samples)\n", path, secs, buf_.size());
        return true;
    }

    size_t sampleCount() const { return buf_.size(); }

private:
    std::vector<int16_t>      ring_;
    std::vector<int16_t>      buf_;    // drained samples
    std::atomic<size_t>       write_{0};
    std::atomic<size_t>       read_ {0};
};
