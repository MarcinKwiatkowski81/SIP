// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// receive_and_record.cpp
// ──────────────────────────────────────────────────────────────────────────────
// Registers as a SIP extension, waits for incoming calls, auto-answers each
// one, plays a WAV file to the caller, records inbound audio, and prints any
// DTMF digits received (RFC 4733 RTP or SIP INFO).
//
// Each call is handled in its own CallSlot so multiple simultaneous calls are
// fully isolated: separate WavReader, WavWriter, playback thread, and output
// file named  recorded_<N>.wav  (N = slot index).
//
// Build:  see CMakeLists.txt  (target: receive_and_record)
//
// Usage:
//   ./receive_and_record
//       -a 192.168.1.x     # Asterisk / registrar IP
//       -l 192.168.1.y     # local IP (must be reachable by Asterisk)
//       [-w greeting.wav]  # WAV to play to every caller  (default: test.wav)
//       [-o recorded]      # output filename prefix        (default: recorded)
//       [-p 5060]          # registrar SIP port            (default: 5060)
//       [-P 5062]          # local SIP port                (default: 5062)
//       [-u user]          # SIP username / extension      (default: 7000)
//       [-s password]      # SIP password                  (default: secret)
//       [-t 60]            # max per-call duration in s    (default: 60)
//       [-c 8]             # max simultaneous calls        (default: 8)
// ──────────────────────────────────────────────────────────────────────────────
#include "SipStack.h"
#include "WavFile.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/time.h>
#include <atomic>
#include <mutex>
#include <string>

using namespace sip;

// ── Constants / tunables ──────────────────────────────────────────────────────
static constexpr size_t MAX_CALLS = 32;   // hard upper bound for slot array

// ── Program-wide config (set once in main, then read-only) ───────────────────
static const char*  g_wavIn    = "test.wav";
static const char*  g_outPfx   = "recorded";
static int          g_maxSecs  = 60;
static size_t       g_maxCalls = 8;

// ── Quit flag ─────────────────────────────────────────────────────────────────
static std::atomic<bool> g_quit{false};
static void sigHandler(int) { g_quit = true; }

static int64_t msNow() {
    struct timeval tv; gettimeofday(&tv, nullptr);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/** Convert a DTMF digit code (0–15) to its printable character. */
static char dtmfChar(uint8_t digit) {
    if (digit <= 9)  return (char)('0' + digit);
    if (digit == 10) return '*';
    if (digit == 11) return '#';
    if (digit <= 15) return (char)('A' + digit - 12);
    return '?';
}

// ─────────────────────────────────────────────────────────────────────────────
// CallSlot  – all per-call state, fully self-contained
// ─────────────────────────────────────────────────────────────────────────────
struct CallSlot {
    // ── identity ──────────────────────────────────────────────────────────────
    size_t      idx        = 0;           // slot index (for filename/log)
    CallHandle  handle     = InvalidDialog;
    std::string callerUri;

    // ── state flags (written by SIP/RTP threads, read by playback thread) ────
    std::atomic<bool> active   {false};   // slot is in use
    std::atomic<bool> connected{false};   // call answered & RTP up
    std::atomic<bool> hungup   {false};   // BYE received or we hung up

    // ── media ─────────────────────────────────────────────────────────────────
    RtpSession*        rtp     = nullptr;
    WavReader          reader;
    WavWriter          writer;
    RtpSession::Stats  finalStats = {};

    // ── playback thread ───────────────────────────────────────────────────────
    pthread_t  playTid;
    bool       playStarted = false;

    // ── output path ───────────────────────────────────────────────────────────
    char outPath[128] = {};

    // Non-copyable
    CallSlot() = default;
    CallSlot(const CallSlot&) = delete;
    CallSlot& operator=(const CallSlot&) = delete;

    // Reset to idle state (called after call ends and WAV is saved)
    void reset() {
        handle      = InvalidDialog;
        callerUri.clear();
        rtp         = nullptr;
        playStarted = false;
        outPath[0]  = '\0';
        finalStats  = {};
        reader.close();
        // writer: re-construct in place to clear its internal buffers
        writer.~WavWriter();
        new (&writer) WavWriter();
        hungup    .store(false);
        connected .store(false);
        active    .store(false);   // last: makes slot visible as free
    }
};

static CallSlot g_slots[MAX_CALLS];

// ── Slot lookup helpers ───────────────────────────────────────────────────────
// Protected by g_slotsMu only where we allocate/free slots (find + mark active
// is a two-step, so we hold the mutex for both steps together).
static std::mutex g_slotsMu;

static CallSlot* allocSlot() {
    std::lock_guard<std::mutex> lk(g_slotsMu);
    for (size_t i = 0; i < g_maxCalls; ++i) {
        if (!g_slots[i].active.load(std::memory_order_acquire)) {
            g_slots[i].active.store(true, std::memory_order_release);
            return &g_slots[i];
        }
    }
    return nullptr;
}

static CallSlot* findSlot(CallHandle h) {
    for (size_t i = 0; i < g_maxCalls; ++i) {
        if (g_slots[i].active.load(std::memory_order_acquire) &&
            g_slots[i].handle == h)
            return &g_slots[i];
    }
    return nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Playback thread  – one instance per call
// ─────────────────────────────────────────────────────────────────────────────
static void* playbackThread(void* arg) {
    CallSlot* slot = (CallSlot*)arg;
    printf("[PLAY][%zu] started  caller=%s\n", slot->idx, slot->callerUri.c_str());

    int16_t frame[WavReader::FRAME];
    int64_t callStart    = msNow();   // for max-duration enforcement
    int64_t nextTx       = callStart;
    int     silFrames    = 0;
    const int SILENCE_FRAMES = 25;   // 25 × 20 ms = 500 ms tail silence

    while (!g_quit && slot->connected.load() && !slot->hungup.load()) {
        int64_t now = msNow();
        if (now < nextTx) {
            struct timespec ts = {0, (nextTx - now) * 1000000L};
            nanosleep(&ts, nullptr);
        }
        nextTx += 20;

        // Snapshot rtp pointer once per frame: onBye() can set slot->rtp=nullptr
        // on the SIP thread at any time, so we must not read it twice.
        RtpSession* rtp = slot->rtp;
        if (!rtp || !rtp->isOpen()) continue;

        // Enforce max call duration (callStart is captured once, before the loop)
        if (g_maxSecs > 0 && msNow() - callStart >= (int64_t)g_maxSecs * 1000) {
            printf("[PLAY][%zu] max duration reached (%d s)\n",
                   slot->idx, g_maxSecs);
            break;
        }

        if (!slot->reader.done()) {
            slot->reader.nextFrame(frame);
        } else {
            memset(frame, 0, sizeof frame);
            if (++silFrames >= SILENCE_FRAMES) {
                printf("[PLAY][%zu] EOF — hanging up\n", slot->idx);
                break;
            }
        }
        rtp->sendAudio(frame, WavReader::FRAME);
    }

    printf("[PLAY][%zu] thread done\n", slot->idx);
    slot->hungup.store(true);
    return nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Finalise a call: save WAV, print stats, reset slot
// Called from the main loop once hungup is observed.
// gStack must be set before any call can arrive.
// ─────────────────────────────────────────────────────────────────────────────
static SipStack* g_stack = nullptr;

static void finaliseCall(CallSlot* slot) {
    // Send BYE if we're still the connected side (e.g. max-duration hangup)
    if (slot->connected.load() && g_stack) {
        printf("[SIP][%zu] sending BYE\n", slot->idx);
        g_stack->bye(slot->handle);
        // onBye will set connected=false; wait briefly for it
        int64_t deadline = msNow() + 2000;
        while (slot->connected.load() && msNow() < deadline) {
            struct timespec ts = {0, 20 * 1000000L};
            nanosleep(&ts, nullptr);
        }
    }

    // Join playback thread
    if (slot->playStarted) {
        pthread_join(slot->playTid, nullptr);
        slot->playStarted = false;
    }

    // Flush writer and save WAV
    slot->writer.drain();
    if (slot->writer.sampleCount() > 0) {
        printf("[REC][%zu] saving %zu samples to '%s'\n",
               slot->idx, slot->writer.sampleCount(), slot->outPath);
        slot->writer.save(slot->outPath);
    } else {
        printf("[REC][%zu] no audio recorded\n", slot->idx);
    }

    // Print per-call stats
    const auto& st = slot->finalStats;
    printf("[STATS][%zu] TX %llu pkts / %llu B   RX %llu pkts / %llu B"
           "   lost=%u  jitter=%.1f ms\n",
           slot->idx,
           (unsigned long long)st.txPkts, (unsigned long long)st.txBytes,
           (unsigned long long)st.rxPkts, (unsigned long long)st.rxBytes,
           st.rxLost, st.jitterMs);

    slot->reset();
}

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    const char* asteriskIP   = nullptr;
    const char* localIP      = nullptr;
    const char* sipUser      = "7000";
    const char* sipPassword  = "secret";
    uint16_t    asteriskPort = 5060;
    uint16_t    localPort    = 5062;

    int opt;
    while ((opt = getopt(argc, argv, "a:l:w:o:p:P:u:s:t:c:h")) != -1) {
        switch (opt) {
        case 'a': asteriskIP   = optarg;                        break;
        case 'l': localIP      = optarg;                        break;
        case 'w': g_wavIn      = optarg;                        break;
        case 'o': g_outPfx     = optarg;                        break;
        case 'p': asteriskPort = (uint16_t)atoi(optarg);        break;
        case 'P': localPort    = (uint16_t)atoi(optarg);        break;
        case 'u': sipUser      = optarg;                        break;
        case 's': sipPassword  = optarg;                        break;
        case 't': g_maxSecs    = atoi(optarg);                  break;
        case 'c': g_maxCalls   = (size_t)atoi(optarg);          break;
        default:
            printf("Usage: %s -a <registrar-ip> -l <local-ip>\n"
                   "  [-w greeting.wav]  WAV to play to caller   (default: test.wav)\n"
                   "  [-o prefix]        output filename prefix   (default: recorded)\n"
                   "  [-p port]          registrar SIP port       (default: 5060)\n"
                   "  [-P port]          local SIP port           (default: 5062)\n"
                   "  [-u user]          SIP username             (default: 7000)\n"
                   "  [-s pass]          SIP password             (default: secret)\n"
                   "  [-t secs]          max call duration        (default: 60)\n"
                   "  [-c n]             max simultaneous calls   (default: 8)\n",
                   argv[0]);
            return 1;
        }
    }
    if (!asteriskIP || !localIP) {
        fputs("Required: -a <registrar-ip>  -l <local-ip>\n", stderr);
        return 1;
    }
    if (g_maxCalls < 1 || g_maxCalls > MAX_CALLS) {
        fprintf(stderr, "Max simultaneous calls must be 1–%zu\n", MAX_CALLS);
        return 1;
    }

    // Assign slot indices once (they never change)
    for (size_t i = 0; i < MAX_CALLS; ++i) g_slots[i].idx = i;

    signal(SIGINT,  sigHandler);
    signal(SIGTERM, sigHandler);

    // ── Stack config ──────────────────────────────────────────────────────────
    StackConfig cfg;
    cfg.localUser.assign(sipUser,     strlen(sipUser));
    cfg.localDomain.assign(asteriskIP, strlen(asteriskIP));
    cfg.localAddr.assign(localIP,      strlen(localIP));
    cfg.rtpLocalAddr  = cfg.localAddr;
    cfg.localPort     = localPort;
    cfg.registrarHost.assign(asteriskIP, strlen(asteriskIP));
    cfg.registrarPort = asteriskPort;
    cfg.authUser.assign(sipUser,     strlen(sipUser));
    cfg.authPass.assign(sipPassword, strlen(sipPassword));
    cfg.regExpires  = 120;
    cfg.rtpBasePort = 17000;

    CodecRegistry codecs;

    // ── Callbacks ─────────────────────────────────────────────────────────────
    StackCallbacks cbs;

    // ── Registration ──────────────────────────────────────────────────────────
    cbs.onRegistered = [sipUser](bool ok, int code) {
        if (ok)
            printf("[SIP] Registered as %s  ok — waiting for calls\n", sipUser);
        else
            fprintf(stderr, "[SIP] Registration FAILED  code=%d\n", code);
    };

    // ── Incoming INVITE ───────────────────────────────────────────────────────
    cbs.onInvite = [](CallHandle h, const SipMessage& msg) {
        printf("[SIP] Incoming call  from=%s  handle=%u\n",
               msg.from.uri.c_str(), (unsigned)h);

        CallSlot* slot = allocSlot();
        if (!slot) {
            printf("[SIP] All %zu slots busy — rejecting call %u\n",
                   g_maxCalls, (unsigned)h);
            if (g_stack) g_stack->reject(h, 486, "Busy Here");
            return;
        }

        slot->handle     = h;
        slot->callerUri  = msg.from.uri.c_str();
        snprintf(slot->outPath, sizeof slot->outPath,
                 "%s_%zu.wav", g_outPfx, slot->idx);

        // Open greeting WAV for this call (independent file handle per slot)
        if (!slot->reader.open(g_wavIn)) {
            fprintf(stderr, "[REC][%zu] cannot open '%s' — rejecting\n",
                    slot->idx, g_wavIn);
            if (g_stack) g_stack->reject(h, 500, "Server Internal Error");
            slot->reset();
            return;
        }

        printf("[SIP][%zu] answering  output='%s'\n", slot->idx, slot->outPath);
        if (g_stack) g_stack->accept(h);
    };

    // ── Call connected (2xx + ACK exchanged) ──────────────────────────────────
    cbs.onConnected = [](CallHandle h, RtpSession* rtp) {
        CallSlot* slot = findSlot(h);
        if (!slot) return;

        printf("[SIP][%zu] connected  rtp=%s\n",
               slot->idx, rtp ? "up" : "no-media");

        slot->rtp       = rtp;
        slot->connected.store(true);

        if (rtp) {
            rtp->setCallbacks({
                // onAudio: push decoded PCM into this slot's WAV writer
                [slot](const AudioFrame& f) {
                    slot->writer.push(f.pcm, f.samples);
                },
                // onDtmf: RFC 4733 / RFC 2833 in-band telephone-event
                [slot](uint8_t digit, uint16_t durMs) {
                    printf("[DTMF][%zu] call=%u  digit=%c  duration=%u ms"
                           "  (RFC 4733 RTP)\n",
                           slot->idx, (unsigned)slot->handle,
                           dtmfChar(digit), (unsigned)durMs);
                },
                nullptr   // onRawRtp
            });
            printf("[REC][%zu] recording wired to RTP onAudio callback\n",
                   slot->idx);
        }

        // Start playback thread for this slot
        slot->playStarted = true;
        pthread_create(&slot->playTid, nullptr, playbackThread, slot);
    };

    // ── DTMF via SIP INFO ─────────────────────────────────────────────────────
    cbs.onDtmf = [](CallHandle h, uint8_t digit, uint16_t durMs) {
        CallSlot* slot = findSlot(h);
        size_t idx = slot ? slot->idx : SIZE_MAX;
        printf("[DTMF][%zu] call=%u  digit=%c  duration=%u ms  (SIP INFO)\n",
               idx, (unsigned)h, dtmfChar(digit), (unsigned)durMs);
    };

    // ── Call ended ────────────────────────────────────────────────────────────
    cbs.onBye = [](CallHandle h, int code) {
        CallSlot* slot = findSlot(h);
        if (!slot) return;
        printf("[SIP][%zu] call ended  code=%d\n", slot->idx, code);
        if (slot->rtp) slot->finalStats = slot->rtp->stats();
        slot->rtp       = nullptr;
        slot->connected.store(false);
        slot->hungup.store(true);
    };

    // ── Init stack ────────────────────────────────────────────────────────────
    SipStack stack;
    g_stack = &stack;
    if (!stack.init(cfg, cbs, &codecs)) {
        fputs("[SIP] Stack init failed\n", stderr);
        return 1;
    }

    // ── Tick thread ───────────────────────────────────────────────────────────
    pthread_t tickTid;
    auto tickFn = [](void* arg) -> void* {
        SipStack* s = (SipStack*)arg;
        while (!g_quit) {
            struct timespec ts = {0, 50 * 1000000L};
            nanosleep(&ts, nullptr);
            s->tick();
        }
        return nullptr;
    };
    pthread_create(&tickTid, nullptr, +tickFn, &stack);

    // ── Register ──────────────────────────────────────────────────────────────
    printf("[SIP] Registering as %s @ %s:%u ...\n",
           sipUser, asteriskIP, asteriskPort);
    stack.doRegister();

    // ── Main loop ─────────────────────────────────────────────────────────────
    // Periodically:
    //   1. Drain WavWriter ring buffers for active calls.
    //   2. Detect calls that have hung up and finalise them.
    printf("[MAIN] running  max_calls=%zu  max_secs=%d  greeting='%s'\n",
           g_maxCalls, g_maxSecs, g_wavIn);
    printf("[MAIN] press Ctrl-C to stop\n");

    while (!g_quit) {
        struct timespec ts = {0, 100 * 1000000L};   // 100 ms housekeeping cycle
        nanosleep(&ts, nullptr);

        for (size_t i = 0; i < g_maxCalls; ++i) {
            CallSlot* slot = &g_slots[i];
            if (!slot->active.load(std::memory_order_acquire)) continue;

            // Drain writer ring regardless of call state
            slot->writer.drain();

            // Enforce max call duration from the main loop as a safety net
            // (playback thread also enforces it, but may be blocked on nanosleep)
            if (slot->connected.load() && g_maxSecs > 0) {
                // We don't track connect time in the slot yet; the playback
                // thread handles duration enforcement and sets hungup itself.
            }

            // Finalise once the call is fully done
            if (slot->hungup.load()) {
                finaliseCall(slot);
                // slot->active is now false — slot is back in the free pool
            }
        }
    }

    // ── Shutdown: finalise any calls still active ─────────────────────────────
    printf("[MAIN] shutting down ...\n");
    for (size_t i = 0; i < g_maxCalls; ++i) {
        if (g_slots[i].active.load()) {
            g_slots[i].hungup.store(true);   // force playback thread to exit
            finaliseCall(&g_slots[i]);
        }
    }

    pthread_join(tickTid, nullptr);
    stack.shutdown();
    printf("[MAIN] done\n");
    return 0;
}
