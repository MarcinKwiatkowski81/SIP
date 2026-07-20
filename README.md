Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
All rights reserved.


# SIP/RTP Stack

C++17 SIP and RTP stack with:
- SIP UA (`sip_client`)
- SIP server/proxy/B2BUA (`sip_server`)
- Sample PBX with registration and media bridging (`sample_pbx`)
- Media/transcoding smoke tools (`transcode_smoke`)

## License

This software is licensed under GPLv3 for open-source use. For closed-source, commercial, or proprietary deployment, please contact us to purchase a commercial license.

The full GPLv3 license text is available in `LICENSE`.

## Requirements

- Ubuntu Linux
- `cmake` >= 3.16
- C++17 compiler (`g++`/`clang++`)
- `pthread` support

Install base build tools:

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config
```

Install API documentation toolchain (optional):

```bash
sudo apt install -y doxygen graphviz
```

## Optional codec support on Ubuntu

This project can use extra codec libraries when detected:
- GSM (libgsm)
- G.729A (bcg729)
- CODEC2 (codec2)

Install them with apt:

```bash
sudo apt install -y libgsm1-dev libbcg729-dev libcodec2-dev
```

Notes:
- After install, re-run CMake configure so detection is refreshed.
- During configure, you should see lines such as:
  - `Codec: GSM-FR ...`
  - `Codec: G.729A ...`
  - `Codec: CODEC2 ...`

If `libbcg729-dev` is not available in your Ubuntu repo, enable `universe` and retry:

```bash
sudo add-apt-repository universe
sudo apt update
sudo apt install -y libbcg729-dev
```

## Build

From repository root:

```bash
cmake -S . -B build
cmake --build build -j
```

## API documentation (Doxygen)

Generate comprehensive API docs from source comments:

```bash
cmake -S . -B build -DSIP_BUILD_DOCS=ON
cmake --build build --target docs
```

Open generated docs:

- `build/docs/html/index.html`

Documentation sources:
- `docs/mainpage.md`
- public API headers in `include/`

## Main binaries

- `build/sip_client`
- `build/sip_server`
- `build/call_and_record`
- `build/sample_pbx`
- `build/transcode_smoke`

## Quick PBX start

Run sample PBX:

```bash
./build/sample_pbx -l 192.168.1.10 -d pbx.local -x 100-120 -e alice
```

Credential policy in `sample_pbx`:
- username is the extension
- password is `pass_` + username

Examples:
- `100` / `pass_100`
- `alice` / `pass_alice`

Detailed PBX usage and endpoint setup:
- `samples/pbx/README.md`
- `samples/pbx/endpoints/linphone.md`
- `samples/pbx/endpoints/zoiper.md`

## Transcoding smoke checks

Basic check:

```bash
./build/transcode_smoke -a PCMU -b PCMA
```

RTP-path check:

```bash
./build/transcode_smoke --rtp-path -a PCMU -b PCMA
```

Stream check with synthetic loss:

```bash
./build/transcode_smoke --stream 200 --simulate-loss 10 -a PCMU -b PCMA
```

## Troubleshooting

### Optional codecs not detected by CMake

Symptoms:
- configure output does not show one or more of:
  - `Codec: GSM-FR ...`
  - `Codec: G.729A ...`
  - `Codec: CODEC2 ...`

Checks and fixes:

1. Verify packages are installed:

```bash
dpkg -l | grep -E 'libgsm1-dev|libbcg729-dev|libcodec2-dev'
```

2. Refresh CMake cache and reconfigure:

```bash
rm -rf build
cmake -S . -B build
```

3. If `libbcg729-dev` is missing from apt indexes, enable `universe`:

```bash
sudo add-apt-repository universe
sudo apt update
sudo apt install -y libbcg729-dev
```

4. Confirm libraries are present on disk:

```bash
ls -l /usr/lib/x86_64-linux-gnu/libgsm.so* \
      /usr/lib/x86_64-linux-gnu/libbcg729.so* \
      /usr/lib/x86_64-linux-gnu/libcodec2.so*
```

5. Re-run configure and check codec summary lines:

```bash
cmake -S . -B build
```

If you use a non-standard library path, adjust `CMakeLists.txt` hints or install the dev package into standard system locations.

One-command diagnostics helper:

```bash
./samples/pbx/codec_diagnostics.sh
```

This script prints package status, discovered codec libraries, CMake cache codec hints, and fresh configure summary lines.

Note: this project currently detects codec shared libraries directly during CMake configure, so codec support may appear enabled even when the matching `-dev` package is missing.
