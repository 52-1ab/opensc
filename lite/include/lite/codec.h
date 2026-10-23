#ifndef LITE_CODEC_H
#define LITE_CODEC_H

#include <stddef.h>
#include <stdint.h>

// Android base64 flags we reproduce: DEFAULT wraps at 76 and appends '\n'; NO_WRAP does neither.
enum { LITE_B64_DEFAULT = 0, LITE_B64_NO_WRAP = 2 };

size_t lite_b64_encode_len(size_t in_len, int flag);
size_t lite_b64_encode(const uint8_t *in, size_t in_len, int flag, char *out, size_t out_cap);

size_t lite_b64_decode_len(size_t in_len);
long lite_b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap);

size_t lite_hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);
long lite_hex_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap);

#endif
