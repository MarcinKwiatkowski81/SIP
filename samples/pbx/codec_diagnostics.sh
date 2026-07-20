#!/usr/bin/env bash
# Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
# All rights reserved.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

print_header() {
  echo
  echo "== $1 =="
}

print_header "System"
echo "Date: $(date -Is)"
echo "Host: $(hostname)"
echo "Kernel: $(uname -srmo)"

print_header "Ubuntu release"
if [[ -f /etc/os-release ]]; then
  grep -E '^(NAME|VERSION|VERSION_CODENAME)=' /etc/os-release || true
else
  echo "/etc/os-release not found"
fi

print_header "APT package status"
for pkg in libgsm1-dev libbcg729-dev libcodec2-dev cmake build-essential pkg-config; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    ver="$(dpkg -s "$pkg" | awk -F': ' '/^Version:/{print $2; exit}')"
    echo "OK   $pkg ${ver:-unknown-version}"
  else
    echo "MISS $pkg"
  fi
done

print_header "Library files"
shopt -s nullglob
libs=(
  /usr/lib/x86_64-linux-gnu/libgsm.so*
  /usr/lib/x86_64-linux-gnu/libbcg729.so*
  /usr/lib/x86_64-linux-gnu/libcodec2.so*
)
if [[ ${#libs[@]} -eq 0 ]]; then
  echo "No codec shared libraries found under /usr/lib/x86_64-linux-gnu"
else
  printf '%s\n' "${libs[@]}"
fi
shopt -u nullglob

print_header "CMake cache codec hints"
if [[ -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  grep -E 'LIB_GSM|LIB_BCG729|LIB_CODEC2' "${BUILD_DIR}/CMakeCache.txt" || true
else
  echo "No build/CMakeCache.txt found"
fi

print_header "Fresh configure check"
cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" 2>&1 | tee "${BUILD_DIR}/codec_diagnostics_configure.log" >/dev/null

grep -E 'Codec:|Codecs:' "${BUILD_DIR}/codec_diagnostics_configure.log" || true

print_header "Tips"
cat <<'EOF'
If a codec is missing:
1) Install package(s):
   sudo apt update
   sudo apt install -y libgsm1-dev libbcg729-dev libcodec2-dev
2) If libbcg729-dev is unavailable:
   sudo add-apt-repository universe
   sudo apt update
   sudo apt install -y libbcg729-dev
3) Re-run this diagnostic script.

Note:
- CMake in this project detects shared libraries directly, so codec support can be enabled
  even if a -dev package is not installed.
- Installing -dev packages is still recommended for a clean, reproducible setup.
EOF
