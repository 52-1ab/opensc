#include "lite/codec.h"
#include "testutil.h"

int main(void) {
    char out[512];
    uint8_t raw[512];

    const char *msg = "hello, world!";
    size_t n = lite_b64_encode((const uint8_t *)msg, strlen(msg), LITE_B64_NO_WRAP, out, sizeof out);
    CHECK(n == 20);
    CHECK_STR(out, "aGVsbG8sIHdvcmxkIQ==");

    n = lite_b64_encode((const uint8_t *)msg, strlen(msg), LITE_B64_DEFAULT, out, sizeof out);
    CHECK_STR(out, "aGVsbG8sIHdvcmxkIQ==\n");

    long d = lite_b64_decode(out, n, raw, sizeof raw);
    CHECK(d == (long)strlen(msg));
    CHECK(memcmp(raw, msg, (size_t)d) == 0);

    uint8_t big[60];
    for (int i = 0; i < 60; i++) big[i] = (uint8_t)i;
    n = lite_b64_encode(big, sizeof big, LITE_B64_DEFAULT, out, sizeof out);
    CHECK(out[76] == '\n');
    CHECK(out[n - 1] == '\n');
    d = lite_b64_decode(out, n, raw, sizeof raw);
    CHECK(d == 60 && memcmp(raw, big, 60) == 0);

    uint8_t hb[] = {0xde, 0xad, 0xbe, 0xef};
    lite_hex_encode(hb, sizeof hb, out, sizeof out);
    CHECK_STR(out, "deadbeef");
    d = lite_hex_decode("deadbeef", 8, raw, sizeof raw);
    CHECK(d == 4 && memcmp(raw, hb, 4) == 0);

    printf("test_codec");
    DONE();
}
