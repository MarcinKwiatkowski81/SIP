#!/usr/bin/env python3
# Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
# All rights reserved.

"""
generate_test_wav.py  –  Create test.wav: 8 kHz mono 16-bit PCM
Produces a 5-second audio clip:
  0.0–0.5 s  : 440 Hz tone (A4) — "attention"
  0.5–1.0 s  : silence
  1.0–1.5 s  : 880 Hz tone (A5)
  1.5–2.0 s  : silence
  2.0–4.0 s  : 697 Hz + 1209 Hz dual tone (DTMF '1' — demo frequency pair)
  4.0–5.0 s  : fade-out sine sweep 1000→500 Hz

All transitions are cosine-windowed to avoid clicks.
Output: test.wav in the current directory.
"""

import struct, math, sys, os

RATE     = 8000
DURATION = 5.0
AMPLITUDE = 16000   # 16-bit signed → ±32767; 16000 ≈ –6 dBFS

def silence(n: int) -> list:
    return [0] * n

def tone(freq: float, n_samp: int, phase0: float = 0.0,
         amp: int = AMPLITUDE, fade_in: int = 80, fade_out: int = 80) -> list:
    """Sine tone with cosine fade-in/out to suppress clicks."""
    samples = []
    for i in range(n_samp):
        t   = i / RATE
        val = amp * math.sin(2 * math.pi * freq * t + phase0)
        # fade
        if i < fade_in:
            val *= (1 - math.cos(math.pi * i / fade_in)) / 2
        elif i >= n_samp - fade_out:
            val *= (1 - math.cos(math.pi * (n_samp - i) / fade_out)) / 2
        samples.append(int(val))
    return samples

def dual_tone(f1: float, f2: float, n_samp: int,
              amp: int = AMPLITUDE // 2) -> list:
    """Sum of two sines (e.g. DTMF), each at half amplitude to avoid clipping."""
    s1 = tone(f1, n_samp, amp=amp, fade_in=80, fade_out=80)
    s2 = tone(f2, n_samp, amp=amp, fade_in=80, fade_out=80)
    return [s1[i] + s2[i] for i in range(n_samp)]

def sweep(f_start: float, f_end: float, n_samp: int,
          amp: int = AMPLITUDE) -> list:
    """Linear frequency sweep (chirp)."""
    samples = []
    for i in range(n_samp):
        t   = i / RATE
        f   = f_start + (f_end - f_start) * i / n_samp
        val = amp * math.sin(2 * math.pi * f * t)
        # fade out
        fade = 160
        if i >= n_samp - fade:
            val *= (n_samp - i) / fade
        samples.append(int(val))
    return samples

def build_pcm() -> list:
    R = RATE
    segments = [
        tone(440,  int(0.5 * R)),           # 440 Hz  0.0–0.5 s
        silence(int(0.5 * R)),              # silence 0.5–1.0 s
        tone(880,  int(0.5 * R)),           # 880 Hz  1.0–1.5 s
        silence(int(0.5 * R)),              # silence 1.5–2.0 s
        dual_tone(697, 1209, int(2.0 * R)), # DTMF '1' 2.0–4.0 s
        sweep(1000, 500, int(1.0 * R)),     # sweep   4.0–5.0 s
    ]
    out = []
    for s in segments:
        out.extend(s)
    return out

def write_wav(path: str, samples: list, rate: int = RATE):
    data = struct.pack(f"<{len(samples)}h", *samples)
    with open(path, "wb") as f:
        # RIFF header
        f.write(b"RIFF")
        f.write(struct.pack("<I", 36 + len(data)))
        f.write(b"WAVE")
        # fmt chunk
        f.write(b"fmt ")
        f.write(struct.pack("<IHHIIHH",
            16,         # chunk size
            1,          # PCM
            1,          # mono
            rate,       # sample rate
            rate * 2,   # byte rate
            2,          # block align
            16))        # bits per sample
        # data chunk
        f.write(b"data")
        f.write(struct.pack("<I", len(data)))
        f.write(data)
    secs = len(samples) / rate
    print(f"Wrote '{path}'  {secs:.2f} s  {len(samples)} samples  {len(data)} bytes")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "test.wav"
    pcm = build_pcm()
    write_wav(out, pcm)
    print(f"Peak amplitude: {max(abs(s) for s in pcm)}")
