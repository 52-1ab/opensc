#ifndef LITE_CODEC_H
#define LITE_CODEC_H

#include <stddef.h>
#include <stdint.h>

/// @file
/// Base64 and hex, reproducing Android's two base64 flags exactly.

/// Android base64 flags: DEFAULT wraps at 76 chars and appends '\n'; NO_WRAP does neither.
enum { LITE_B64_DEFAULT = 0, LITE_B64_NO_WRAP = 2 };

/// Buffer size (incl. NUL) needed to base64-encode `in_len` bytes under `flag`.
size_t lite_b64_encode_len(size_t in_len, int flag);

/// Base64-encodes `in_len` bytes into `out` (NUL-terminated); returns chars written, 0 if `out_cap` too small.
size_t lite_b64_encode(const uint8_t *in, size_t in_len, int flag, char *out, size_t out_cap);

/// Upper bound on bytes produced by decoding a base64 string of `in_len` chars.
size_t lite_b64_decode_len(size_t in_len);

/// Base64-decodes `in_len` chars into `out`; returns bytes written, or -1 if `out_cap` too small.
long lite_b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap);

/// Lowercase-hex-encodes `in_len` bytes into `out` (NUL-terminated); returns chars written, 0 on overflow.
size_t lite_hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

/// Hex-decodes `in_len` chars into `out`; returns bytes written, or -1 on bad input or overflow.
long lite_hex_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap);

#endif
