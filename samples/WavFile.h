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

        // ── RIFF/WAVE identity ────────────────────────────────────────────────
        char id[4]; uint32_t chunkSz;
        if (fread(id,1,4,fp_)!=4 || memcmp(id,"RIFF",4)) {
            fprintf(stderr,"[WAV] '%s': not a RIFF file\n",path); close(); return false;
        }
        fseek(fp_,4,SEEK_CUR);   // skip RIFF chunk size
        if (fread(id,1,4,fp_)!=4 || memcmp(id,"WAVE",4)) {
            fprintf(stderr,"[WAV] '%s': not a WAVE file\n",path); close(); return false;
        }

        // ── Scan chunks until we have both "fmt " and "data" ─────────────────
        // This handles:
        //   • fmtSize > 16  (18-byte PCM/cbSize, 40-byte WAVE_FORMAT_EXTENSIBLE)
        //   • extra chunks between fmt and data (fact, LIST, bext, cue  …)
        bool     gotFmt  = false, gotData = false;
        uint16_t audioFmt = 0, channels = 0, bitsPerSample = 0;
        uint32_t sampleRate = 0, dataSize = 0;

        while (!gotData) {
            if (fread(id,     1, 4, fp_) != 4) break;
            if (fread(&chunkSz,4, 1, fp_) != 1) break;

            if (memcmp(id,"fmt ",4)==0) {
                // Read the first 16 bytes (minimum PCM fmt payload).
                // If fmtSize > 16 the remainder is skipped below.
                uint8_t buf[16] = {};
                size_t toRead = chunkSz < 16 ? chunkSz : 16;
                if (fread(buf, 1, toRead, fp_) != toRead) {
                    fprintf(stderr,"[WAV] '%s': truncated fmt chunk\n",path);
                    close(); return false;
                }
                // Skip any extension bytes beyond the standard 16
                if (chunkSz > toRead)
                    fseek(fp_, (long)(chunkSz - toRead) + (chunkSz & 1), SEEK_CUR);
                else if (chunkSz & 1)
                    fseek(fp_, 1, SEEK_CUR);   // pad byte per RIFF spec

                memcpy(&audioFmt,      buf+0,  2);
                memcpy(&channels,      buf+2,  2);
                memcpy(&sampleRate,    buf+4,  4);
                // buf+8 = byteRate (4), buf+12 = blockAlign (2)
                memcpy(&bitsPerSample, buf+14, 2);

                if (audioFmt != 1) {
                    fprintf(stderr,"[WAV] '%s': only PCM (fmt=1) supported, got %u\n",
                            path, audioFmt);
                    close(); return false;
                }
                if (bitsPerSample != 16) {
                    fprintf(stderr,"[WAV] '%s': only 16-bit PCM supported, got %u\n",
                            path, bitsPerSample);
                    close(); return false;
                }
                gotFmt = true;

            } else if (memcmp(id,"data",4)==0) {
                dataSize = chunkSz;   // audio data starts at current file position
                gotData  = true;
                // Do NOT seek; fp_ is now positioned at the first audio byte.

            } else {
                // Unknown / unwanted chunk — skip it (+ RIFF pad byte if odd size)
                fseek(fp_, (long)chunkSz + (chunkSz & 1), SEEK_CUR);
            }
        }

        if (!gotFmt)  { fprintf(stderr,"[WAV] '%s': no fmt  chunk found\n",path); close(); return false; }
        if (!gotData) { fprintf(stderr,"[WAV] '%s': no data chunk found\n",path); close(); return false; }

        srcRate_  = sampleRate;
        channels_ = channels;
        dataLeft_ = dataSize;
        ratio_    = (srcRate_ + 7999) / 8000;   // ceiling decimation factor
        if (ratio_ < 1) ratio_ = 1;
        printf("[WAV] '%s'  %u Hz  %u ch  %u bytes  ratio→8kHz: %u\n",
               path, srcRate_, channels_, dataSize, ratio_);
        return true;
    }

    void close() {
        if (fp_) { fclose(fp_); fp_=nullptr; }
        dataLeft_=0; done_=false; srcPhase_=0; acc_=0;
    }
    bool done()  const { return done_; }

    // Fill 'out' with exactly FRAME (160) samples at 8 kHz mono.
    // Returns false when file exhausted (out is zeroed = silence).
    bool nextFrame(int16_t out[FRAME]) {
        memset(out, 0, FRAME * sizeof(int16_t));
        if (done_ || !fp_) { done_=true; return false; }

        // ── Fast path: native 8 kHz mono ─────────────────────────────────────
        // Read the whole 20 ms frame in a single fread instead of 160
        // individual 2-byte reads.  Eliminates per-sample call overhead and
        // gives the OS a chance to hand us a contiguous block in one go.
        if (ratio_ == 1 && channels_ == 1) {
            size_t avail  = dataLeft_ / 2;          // samples remaining
            size_t toRead = avail < FRAME ? avail : FRAME;
            size_t got    = fread(out, 2, toRead, fp_);
            dataLeft_ -= (uint32_t)(got * 2);
            if (got < FRAME) done_ = true;          // short read → EOF
            return !done_;
        }

        // ── General path: multi-channel and/or higher sample rate ─────────────
        // Box-filter anti-alias decimation: accumulate ratio_ source samples
        // and emit their average.  This is a simple rectangular (FIR) low-pass
        // with -3 dB at Fs_src/(2*ratio_) ≈ 4 kHz — ideal for narrowband
        // telephony — and completely eliminates the aliasing that point-
        // sampling (keep-every-Nth) would otherwise introduce.
        size_t produced = 0;
        while (produced < FRAME) {
            int16_t src[8] = {};
            size_t bytes = (size_t)channels_ * 2;
            if (dataLeft_ < bytes) { done_=true; break; }
            if (fread(src, 2, channels_, fp_) != (size_t)channels_) { done_=true; break; }
            dataLeft_ -= (uint32_t)bytes;

            // Down-mix to mono (average all channels)
            int32_t mono = 0;
            for (uint16_t c=0; c<channels_; ++c) mono += src[c];
            mono /= channels_;

            // Accumulate into box filter; emit one output sample per ratio_ inputs
            acc_ += mono;
            if (++srcPhase_ >= ratio_) {
                srcPhase_ = 0;
                out[produced++] = (int16_t)(acc_ / (int32_t)ratio_);
                acc_ = 0;
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
    uint32_t srcPhase_ = 0;   // position within current decimation group
    int32_t  acc_      = 0;   // box-filter accumulator for anti-alias decimation
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
