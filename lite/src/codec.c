#include "lite/codec.h"

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t lite_b64_encode_len(size_t in_len, int flag) {
    size_t groups = (in_len + 2) / 3;
    size_t n = groups * 4;
    if (flag == LITE_B64_DEFAULT) {
        size_t lines = n == 0 ? 1 : (n + 75) / 76;
        n += lines;
    }
    return n + 1;
}

// Matches android.util.Base64: DEFAULT inserts '\n' every 76 output chars and a trailing '\n'.
size_t lite_b64_encode(const uint8_t *in, size_t in_len, int flag, char *out, size_t out_cap) {
    size_t o = 0, col = 0;
    int wrap = (flag == LITE_B64_DEFAULT);
    size_t i = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        if (o + 4 >= out_cap) return 0;
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
        out[o++] = B64[v & 63];
        col += 4;
        i += 3;
        if (wrap && col == 76 && i < in_len) { out[o++] = '\n'; col = 0; }
    }
    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (o + 4 >= out_cap) return 0;
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        if (o + 4 >= out_cap) return 0;
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
        out[o++] = '=';
    }
    if (wrap) { if (o + 1 >= out_cap) return 0; out[o++] = '\n'; }
    if (o >= out_cap) return 0;
    out[o] = '\0';
    return o;
}

size_t lite_b64_decode_len(size_t in_len) { return (in_len / 4 + 1) * 3 + 3; }

long lite_b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
    size_t o = 0;
    int vals[4], nv = 0;
    for (size_t i = 0; i < in_len; i++) {
        if (in[i] == '=') break;
        int v = b64_val((uint8_t)in[i]);
        if (v < 0) continue;
        vals[nv++] = v;
        if (nv == 4) {
            if (o + 3 > out_cap) return -1;
            out[o++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
            out[o++] = (uint8_t)(((vals[1] & 0xF) << 4) | (vals[2] >> 2));
            out[o++] = (uint8_t)(((vals[2] & 0x3) << 6) | vals[3]);
            nv = 0;
        }
    }
    if (nv == 3) {
        if (o + 2 > out_cap) return -1;
        out[o++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
        out[o++] = (uint8_t)(((vals[1] & 0xF) << 4) | (vals[2] >> 2));
    } else if (nv == 2) {
        if (o + 1 > out_cap) return -1;
        out[o++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
    }
    return (long)o;
}

static const char HEX[] = "0123456789abcdef";

size_t lite_hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    if (out_cap < in_len * 2 + 1) return 0;
    for (size_t i = 0; i < in_len; i++) {
        out[2 * i] = HEX[in[i] >> 4];
        out[2 * i + 1] = HEX[in[i] & 0xF];
    }
    out[in_len * 2] = '\0';
    return in_len * 2;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

long lite_hex_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
    size_t n = in_len / 2;
    if (n > out_cap) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_val(in[2 * i]), lo = hex_val(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (long)n;
}
