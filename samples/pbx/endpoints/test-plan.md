Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
All rights reserved.


# Quick interoperability test plan

1. Start PBX.
2. Register endpoint `100` and `101` with passwords `pass_100` and `pass_101`.
3. Force endpoint codec preference mismatch (PCMU-first vs PCMA-first).
4. Place call `100 -> 101`.
5. Confirm two-way audio.
6. Confirm PBX log line includes `Codec bridge active` when payload types differ.

RTP-path smoke validation:
1. Run `./build/transcode_smoke --rtp-path -a PCMU -b PCMA`.
2. Verify both directions print `OK`.

RTP stream continuity validation:
1. Run `./build/transcode_smoke --stream 200 -a PCMU -b PCMA`.
2. Verify dropped frames are within tolerance and both directions print `OK`.

RTP synthetic loss validation:
1. Run `./build/transcode_smoke --stream 200 --simulate-loss 10 -a PCMU -b PCMA`.
2. Verify simulated and dropped counters are reported, and both directions print `OK`.

Optional plugin test:
1. Start PBX with one or more `-g /path/to/codec.so` options.
2. Enable plugin codec on one endpoint and fallback codec on the other.
3. Place a call and validate audio continuity.
