Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
All rights reserved.


# sample_pbx

Small modular PBX built on this SIP/RTP stack.

Features:
- SIP endpoint registration with digest authentication.
- Username is the extension and can be dialed directly.
- Password policy: `pass_` + `username`.
- B2BUA call anchoring with RTP relay.
- Extensible transcoding support in server media relay (mixed endpoint codecs).

## Build

From project root:

```bash
cmake -S . -B build
cmake --build build --target sample_pbx
```

## Run

```bash
./build/sample_pbx -l 192.168.1.10 -d pbx.local -x 100-120 -e alice
```

Load extra codec plugins (optional):

```bash
./build/sample_pbx -l 192.168.1.10 -d pbx.local \
	-g /path/to/codec_a.so \
	-g /path/to/codec_b.so
```

Print active codecs on startup:

```bash
./build/sample_pbx -l 192.168.1.10 -d pbx.local --print-codecs
```

Credentials:
- `100` -> `pass_100`
- `alice` -> `pass_alice`

Suggested endpoint AOR format:
- `sip:<username>@<domain>`

Example dialing:
- Endpoint `100` calls `sip:101@pbx.local`

## Runtime admin commands

- `r`: registrations
- `c`: active calls
- `s`: stats
- `k`: active codecs
- `u`: users
- `q`: quit

## Endpoint setup templates

- Linphone: `samples/pbx/endpoints/linphone.md`
- Zoiper: `samples/pbx/endpoints/zoiper.md`
- Interop test checklist: `samples/pbx/endpoints/test-plan.md`

## Notes on codec bridging

- Out of the box, the PBX can bridge G.711u/PCMU and G.711a/PCMA when endpoints pick different payload types.
- Additional codecs can be loaded with `-g` and used for bridge selection by SDP codec name/payload mapping.

## Offline transcode smoke test

Build and run:

```bash
cmake --build build --target transcode_smoke
./build/transcode_smoke
```

Choose codecs by name:

```bash
./build/transcode_smoke -a PCMU -b PCMA
```

Validate RTP header/payload remap path:

```bash
./build/transcode_smoke --rtp-path -a PCMU -b PCMA
```

Validate multi-frame RTP progression (sequence/timestamp continuity):

```bash
./build/transcode_smoke --stream 200 -a PCMU -b PCMA
```

Stress test with synthetic packet loss (example 10%):

```bash
./build/transcode_smoke --stream 200 --simulate-loss 10 -a PCMU -b PCMA
```

With plugins:

```bash
./build/transcode_smoke -g /path/to/codec.so -a MYCODEC -b PCMU
```

## Codec diagnostics helper

From repository root:

```bash
./samples/pbx/codec_diagnostics.sh
```

The script reports package availability, library presence, CMake codec cache values, and fresh configure codec summary lines.

Note: codec support is detected from shared libraries at configure time, so support can still be enabled even if the matching `-dev` package is not installed.
