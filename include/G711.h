// Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
// All rights reserved.

#pragma once
/**
 * G711.h - ITU-T G.711 mu-law (PCMU, PT=0) and A-law (PCMA, PT=8) codec.
 * References: ITU-T G.711, RFC 3551
 */
#include <cstddef>
#include <cstdint>

namespace G711 {
/** @brief Encode one PCM sample to G.711 u-law byte. */
uint8_t  encodeUlaw(int16_t pcm) noexcept;
/** @brief Decode one G.711 u-law byte to PCM sample. */
int16_t  decodeUlaw(uint8_t ulaw) noexcept;
/** @brief Encode PCM buffer to u-law bytes. */
void encodeBufUlaw(const int16_t* pcm, uint8_t* dst, std::size_t n) noexcept;
/** @brief Decode u-law byte buffer to PCM samples. */
void decodeBufUlaw(const uint8_t* src, int16_t* pcm, std::size_t n) noexcept;
/** @brief Encode one PCM sample to G.711 A-law byte. */
uint8_t  encodeAlaw(int16_t pcm) noexcept;
/** @brief Decode one G.711 A-law byte to PCM sample. */
int16_t  decodeAlaw(uint8_t alaw) noexcept;
/** @brief Encode PCM buffer to A-law bytes. */
void encodeBufAlaw(const int16_t* pcm, uint8_t* dst, std::size_t n) noexcept;
/** @brief Decode A-law byte buffer to PCM samples. */
void decodeBufAlaw(const uint8_t* src, int16_t* pcm, std::size_t n) noexcept;
} // namespace G711
