// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

// call_and_record.cpp
// ──────────────────────────────────────────────────────────────────────────────
// Registers as SIP extension 100 against Asterisk, dials extension 101,
// plays test.wav over RTP, records the remote audio to recorded.wav,
// then hangs up.
//
// Build:  see CMakeLists.txt (target: call_and_record)
//
// Usage:
//   ./call_and_record
//       -a 192.168.1.x     # Asterisk IP
//       -l 192.168.1.y     # local IP (must be reachable by Asterisk)
//       [-w test.wav]      # WAV to play  (default: test.wav)
//       [-o recorded.wav]  # output file  (default: recorded.wav)
//       [-p 5060]          # Asterisk SIP port (default: 5060)
//       [-P 5062]          # local SIP port    (default: 5062)
//       [-s secret]        # SIP password      (default: secret100)
//       [-t 30]            # max call duration in seconds (default: 30)
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

using namespace sip;

// ── Global state shared between threads ───────────────────────────────────────
static std::atomic<bool>        g_quit         {false};
static std::atomic<bool>        g_registered   {false};
static std::atomic<bool>        g_connected    {false};
static std::atomic<bool>        g_hungup       {false};
static std::atomic<CallHandle>  g_call         {InvalidDialog};
static RtpSession*              g_rtp          = nullptr;
static RtpSession::Stats        g_finalStats   = {};  // saved in onBye before rtpFree

static WavReader   g_reader;
static WavWriter   g_writer;

static const char* g_wavIn   = "test.wav";
static const char* g_wavOut  = "recorded.wav";
static int         g_maxSecs = 30;

static void sigHandler(int) { g_quit = true; }

/** Convert a DTMF digit code (0–15) to its printable character. */
static char dtmfChar(uint8_t digit) {
    if (digit <= 9)  return (char)('0' + digit);
    if (digit == 10) return '*';
    if (digit == 11) return '#';
    if (digit <= 15) return (char)('A' + digit - 12);  // A–D
    return '?';
}

static int64_t msNow() {
    struct timeval tv; gettimeofday(&tv, nullptr);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// ── Playback thread ───────────────────────────────────────────────────────────
// Paces one 20 ms G.711 frame every 20 ms from the WAV file.
// After EOF sends 500 ms of silence then signals the main thread to hang up.
static void* playbackThread(void* /*arg*/) {
    printf("[PLAY] started  file='%s'\n", g_wavIn);
    int16_t frame[WavReader::FRAME];
    int64_t nextTx = msNow();
    int     silence = 0;
    const int SILENCE_FRAMES = 25;   // 25 × 20 ms = 500 ms

    while (!g_quit && g_connected.load()) {
        int64_t now = msNow();
        if (now < nextTx) {
            struct timespec ts = {0, (nextTx - now) * 1000000L};
            nanosleep(&ts, nullptr);
        }
        nextTx += 20;

        if (!g_rtp || !g_rtp->isOpen()) continue;

        if (!g_reader.done()) {
            g_reader.nextFrame(frame);
        } else {
            memset(frame, 0, sizeof frame);
            if (++silence >= SILENCE_FRAMES) {
                printf("[PLAY] EOF — hanging up\n");
                break;
            }
        }
        g_rtp->sendAudio(frame, WavReader::FRAME);
    }

    printf("[PLAY] thread done\n");
    g_hungup = true;
    return nullptr;
}

// ── Drain thread ──────────────────────────────────────────────────────────────
// Flushes WavWriter's lock-free ring into its linear buffer every 100 ms.
static void* drainThread(void* /*arg*/) {
    while (!g_quit) {
        struct timespec ts = {0, 100 * 1000000L};
        nanosleep(&ts, nullptr);
        g_writer.drain();
    }
    g_writer.drain();
    return nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    const char* asteriskIP   = nullptr;
    const char* localIP      = nullptr;
    const char* sipUser      = "2005";
    const char* sipPassword  = "haslo_2005";
    int         extension    = 2001;
    uint16_t    asteriskPort = 5060;
    uint16_t    localPort    = 5062;

    int opt;
    while ((opt = getopt(argc, argv, "a:l:w:o:p:P:s:u:t:e:h")) != -1) {
        switch (opt) {
        case 'a': asteriskIP   = optarg;             break;
        case 'l': localIP      = optarg;             break;
        case 'w': g_wavIn      = optarg;             break;
        case 'o': g_wavOut     = optarg;             break;
        case 'p': asteriskPort = (uint16_t)atoi(optarg); break;
        case 'P': localPort    = (uint16_t)atoi(optarg); break;
        case 's': sipPassword  = optarg;             break;
        case 'u': sipUser      = optarg;             break;
        case 't': g_maxSecs    = atoi(optarg);       break;
        case 'e': extension    = atoi(optarg);       break;
        default:
            printf("Usage: %s -a <asterisk-ip> -l <local-ip> "
                   "[-w test.wav] [-o recorded.wav] "
                   "[-p ast-port] [-P local-port] "
                   "[-s password] [-u user] [-e extension] [-t max-secs]\n", argv[0]);
            return 1;
        }
    }
    if (!asteriskIP || !localIP) {
        fputs("Required: -a <asterisk-ip>  -l <local-ip>\n", stderr);
        return 1;
    }

    if (!g_reader.open(g_wavIn)) {
        fprintf(stderr, "Cannot open '%s'. Run: python3 generate_test_wav.py\n", g_wavIn);
        return 1;
    }

    signal(SIGINT,  sigHandler);
    signal(SIGTERM, sigHandler);

    // ── Stack config ──────────────────────────────────────────────────────────
    StackConfig cfg;
    cfg.localUser.assign(sipUser, strlen(sipUser));
    cfg.localDomain.assign(asteriskIP, strlen(asteriskIP));
    cfg.localAddr.assign(localIP,      strlen(localIP));
    cfg.rtpLocalAddr  = cfg.localAddr;
    cfg.localPort     = localPort;
    cfg.registrarHost.assign(asteriskIP, strlen(asteriskIP));
    cfg.registrarPort = asteriskPort;
    cfg.authUser.assign(sipUser, strlen(sipUser));
    cfg.authPass.assign(sipPassword, strlen(sipPassword));
    cfg.regExpires    = 120;
    cfg.rtpBasePort   = 16400;

    // CodecRegistry default-constructs with G711u (PT 0), G711a (PT 8),
    // TelephoneEvent (PT 101) — matching Asterisk 'allow = ulaw/alaw'.
    CodecRegistry codecs;

    StackCallbacks cbs;

    // ── REGISTER result ───────────────────────────────────────────────────────
    cbs.onRegistered = [sipUser](bool ok, int code) {
        if (ok) {
            printf("[SIP] Registered as %s  ok\n", sipUser);
            g_registered = true;
        } else {
            fprintf(stderr, "[SIP] Registration FAILED  code=%d\n", code);
            g_quit = true;
        }
    };

    // ── Call connected ────────────────────────────────────────────────────────
    // Wire the RtpSession's onAudio callback to push decoded PCM into
    // WavWriter.  WavWriter::push() is lock-free, so calling it from
    // the RTP recv thread requires no extra synchronisation.
    cbs.onConnected = [](CallHandle h, RtpSession* rtp) {
        printf("[SIP] Call connected  handle=%u  rtp=%s\n",
               (unsigned)h, rtp ? "up" : "no-media");
        g_call      = h;
        g_rtp       = rtp;
        g_connected = true;

        if (rtp) {
            rtp->setCallbacks({
                // onAudio: push decoded PCM straight into the WAV writer
                [](const AudioFrame& f) { g_writer.push(f.pcm, f.samples); },
                // onDtmf: RFC 4733 / RFC 2833 in-band telephone-event
                [h](uint8_t digit, uint16_t durMs) {
                    printf("[DTMF] call=%u  digit=%c  duration=%u ms  (RFC 4733 RTP)\n",
                           (unsigned)h, dtmfChar(digit), (unsigned)durMs);
                },
                nullptr    // onRawRtp
            });
            printf("[REC] recording wired to RTP onAudio callback\n");
        }
    };

    // ── DTMF received (SIP-INFO out-of-band) ─────────────────────────────────
    // RFC 4733/2833 in-band DTMF is handled above inside rtp->setCallbacks().
    // This callback catches SIP INFO requests carrying application/dtmf-relay
    // or application/dtmf bodies, parsed by SipStack::handleInfo().
    cbs.onDtmf = [](CallHandle h, uint8_t digit, uint16_t durMs) {
        printf("[DTMF] call=%u  digit=%c  duration=%u ms  (SIP INFO)\n",
               (unsigned)h, dtmfChar(digit), (unsigned)durMs);
    };

    // ── Call ended ────────────────────────────────────────────────────────────
    // Snapshot stats here: bye() calls rtpFree() just after this callback
    // returns, zeroing the session. g_rtp is still valid at entry.
    cbs.onBye = [](CallHandle h, int code) {
        printf("[SIP] Call ended  handle=%u  code=%d\n", (unsigned)h, code);
        if ((CallHandle)g_call.load() == h) {
            if (g_rtp) g_finalStats = g_rtp->stats();
            g_rtp       = nullptr;
            g_connected = false;
            g_hungup    = true;
        }
    };

    SipStack stack;
    if (!stack.init(cfg, cbs, &codecs)) {
        fputs("[SIP] Stack init failed\n", stderr);
        return 1;
    }

    // ── Tick + drain threads ──────────────────────────────────────────────────
    pthread_t tickTid, drainTid, playTid;
    bool playStarted = false;

    pthread_create(&drainTid, nullptr, drainThread, nullptr);

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

    // ── Step 1: REGISTER ─────────────────────────────────────────────────────
    printf("[SIP] Registering as %s @ %s:%u ...\n", sipUser, asteriskIP, asteriskPort);
    stack.doRegister();

    int64_t deadline = msNow() + 5000;
    while (!g_registered && !g_quit && msNow() < deadline) {
        struct timespec ts = {0, 50 * 1000000L};
        nanosleep(&ts, nullptr);
    }
    if (!g_registered) {
        fputs("[SIP] Registration timed out\n", stderr);
        g_quit = true;
        goto cleanup;
    }

    {
        // ── Step 2: INVITE ────────────────────────────────────────────────────
        char target[64];
        snprintf(target, sizeof target, "sip:%d@%s", extension, asteriskIP);
        printf("[SIP] Calling %s ...\n", target);

        CallHandle h = stack.call(target);
        if (h == InvalidDialog) {
            fputs("[SIP] call() failed\n", stderr);
            g_quit = true;
            goto cleanup;
        }
        g_call = h;

        printf("[SIP] Waiting for answer ...\n");
        deadline = msNow() + 30000;
        while (!g_connected && !g_hungup && !g_quit && msNow() < deadline) {
            struct timespec ts = {0, 100 * 1000000L};
            nanosleep(&ts, nullptr);
        }
        if (!g_connected) {
            printf("[SIP] No answer / call failed\n");
            stack.cancel(h);
            goto cleanup;
        }

        // ── Step 3: Playback ──────────────────────────────────────────────────
        // Inbound audio is already being captured via RtpSession::onAudio.
        playStarted = true;
        pthread_create(&playTid, nullptr, playbackThread, nullptr);

        // ── Step 4: Wait ──────────────────────────────────────────────────────
        printf("[MAIN] playing '%s'  recording to '%s'  max %d s\n",
               g_wavIn, g_wavOut, g_maxSecs);

        int64_t callStart = msNow();
        while (!g_hungup && !g_quit) {
            struct timespec ts = {0, 200 * 1000000L};
            nanosleep(&ts, nullptr);
            g_writer.drain();
            if (msNow() - callStart > (int64_t)g_maxSecs * 1000) {
                printf("[MAIN] max duration reached — hanging up\n");
                break;
            }
        }

        // ── Step 5: BYE ──────────────────────────────────────────────────────
        if (g_connected.load()) {
            printf("[SIP] Sending BYE ...\n");
            // bye() -> rtpFree() -> RtpSession::close() joins the recv
            // thread BEFORE closing the fd.  All buffered inbound RTP
            // packets are decoded and pushed into WavWriter first.
            stack.bye(g_call.load());
        }

        if (playStarted) pthread_join(playTid, nullptr);

        // All onAudio callbacks done (recv thread joined inside bye()).
        // ── Step 6: Save WAV ────────────────────────────────────────────
        g_writer.drain();
        if (g_writer.sampleCount() > 0) {
            printf("[REC] saving %zu samples to '%s'\n",
                   g_writer.sampleCount(), g_wavOut);
            g_writer.save(g_wavOut);
        } else {
            printf("[REC] no audio recorded (0 samples)\n");
        }
    }

cleanup:
    g_quit = true;
    pthread_join(tickTid,  nullptr);
    pthread_join(drainTid, nullptr);

    stack.shutdown();
    // g_finalStats was captured in onBye before rtpFree() zeroed the session
    printf("\n── Stats ────────────────────────────────────────────────\n");
    printf("  TX:  %llu packets / %llu bytes\n",
           (unsigned long long)g_finalStats.txPkts,
           (unsigned long long)g_finalStats.txBytes);
    printf("  RX:  %llu packets / %llu bytes\n",
           (unsigned long long)g_finalStats.rxPkts,
           (unsigned long long)g_finalStats.rxBytes);
    printf("  Lost: %u  Jitter: %.1f ms\n",
           g_finalStats.rxLost, g_finalStats.jitterMs);
    printf("───────────────────────────────────────────────────\n");
        return 0;
}
