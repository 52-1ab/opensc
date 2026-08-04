// Reimplementation of libSecureComponent.so (NPCI Common Library); build modes documented in HACKING.md.

#if defined(SC_TEST_MAIN) && defined(SC_STDIO_SERVER)
#error "SC_TEST_MAIN and SC_STDIO_SERVER are mutually exclusive build modes"
#endif

#if !defined(SC_TEST_MAIN) && !defined(SC_STDIO_SERVER)
#define SC_JNI_BUILD 1
#endif

#ifdef SC_JNI_BUILD
#include <jni.h>
#endif
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLS "org/npci/upi/security/pinactivitycomponent/OfflineNativeDefenderService"

typedef struct AliasKeys {
    char *alias;
    EVP_PKEY *rsa;
    EVP_PKEY *ec;
    struct AliasKeys *next;
} AliasKeys;

static AliasKeys *g_store = NULL;
static pthread_mutex_t g_store_lock = PTHREAD_MUTEX_INITIALIZER;

static AliasKeys *store_get_or_create(const char *alias) {
    pthread_mutex_lock(&g_store_lock);
    for (AliasKeys *k = g_store; k; k = k->next) {
        if (strcmp(k->alias, alias) == 0) {
            pthread_mutex_unlock(&g_store_lock);
            return k;
        }
    }
    AliasKeys *k = calloc(1, sizeof(AliasKeys));
    k->alias = strdup(alias);
    k->rsa = EVP_RSA_gen(2048);
    k->ec = EVP_EC_gen("prime256v1");
    k->next = g_store;
    g_store = k;
    pthread_mutex_unlock(&g_store_lock);
    return k;
}

#ifdef SC_JNI_BUILD
// GetStringUTFChars gives modified UTF-8, unlike Java's own getBytes(UTF_8); convert by hand instead.
static uint8_t *utf16_to_utf8(JNIEnv *env, jstring s, size_t *out_len) {
    jsize n = (*env)->GetStringLength(env, s);
    const jchar *chars = (*env)->GetStringCritical(env, s, NULL);
    uint8_t *buf = malloc((size_t)n * 4 + 1);
    size_t o = 0;
    for (jsize i = 0; i < n; i++) {
        uint32_t cp = chars[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < n &&
            chars[i + 1] >= 0xDC00 && chars[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (chars[i + 1] - 0xDC00);
            i++;
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            buf[o++] = '?'; // Java's default replacement for an unpaired surrogate
            continue;
        }
        if (cp < 0x80) {
            buf[o++] = (uint8_t)cp;
        } else if (cp < 0x800) {
            buf[o++] = (uint8_t)(0xC0 | (cp >> 6));
            buf[o++] = (uint8_t)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            buf[o++] = (uint8_t)(0xE0 | (cp >> 12));
            buf[o++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            buf[o++] = (uint8_t)(0x80 | (cp & 0x3F));
        } else {
            buf[o++] = (uint8_t)(0xF0 | (cp >> 18));
            buf[o++] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
            buf[o++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            buf[o++] = (uint8_t)(0x80 | (cp & 0x3F));
        }
    }
    (*env)->ReleaseStringCritical(env, s, chars);
    *out_len = o;
    return buf;
}
#endif

#if defined(SC_JNI_BUILD) || defined(SC_TEST_MAIN)
static int b64_val(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// android.util.Base64.decode(sigB64, NO_WRAP): standard alphabet, padding optional.
static uint8_t *b64_decode(const char *in, size_t in_len, size_t *out_len) {
    uint8_t *out = malloc(in_len * 3 / 4 + 4);
    size_t o = 0;
    int vals[4], nv = 0;
    for (size_t i = 0; i < in_len; i++) {
        if (in[i] == '=') break;
        int v = b64_val((uint8_t)in[i]);
        if (v < 0) continue;
        vals[nv++] = v;
        if (nv == 4) {
            out[o++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
            out[o++] = (uint8_t)(((vals[1] & 0xF) << 4) | (vals[2] >> 2));
            out[o++] = (uint8_t)(((vals[2] & 0x3) << 6) | vals[3]);
            nv = 0;
        }
    }
    if (nv == 3) {
        out[o++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
        out[o++] = (uint8_t)(((vals[1] & 0xF) << 4) | (vals[2] >> 2));
    } else if (nv == 2) {
        out[o++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
    }
    *out_len = o;
    return out;
}
#endif

// Java's "SHA512withRSA/PSS" (no JCA alias) is RSASSA-PSS with SHA-512/MGF1-SHA-512/saltLen=64.
static uint8_t *rsa_pss_sign(EVP_PKEY *key, const uint8_t *msg, size_t msg_len, size_t *sig_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    EVP_DigestSignInit(mdctx, &pctx, EVP_sha512(), NULL, key);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha512());
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    size_t needed = 0;
    EVP_DigestSign(mdctx, NULL, &needed, msg, msg_len);
    uint8_t *sig = malloc(needed);
    EVP_DigestSign(mdctx, sig, &needed, msg, msg_len);
    *sig_len = needed;
    EVP_MD_CTX_free(mdctx);
    return sig;
}

static uint8_t *ecdsa_sign(EVP_PKEY *key, const uint8_t *msg, size_t msg_len, size_t *sig_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key);
    size_t needed = 0;
    EVP_DigestSign(mdctx, NULL, &needed, msg, msg_len);
    uint8_t *sig = malloc(needed);
    EVP_DigestSign(mdctx, sig, &needed, msg, msg_len);
    *sig_len = needed;
    EVP_MD_CTX_free(mdctx);
    return sig;
}

static int ecdsa_verify(EVP_PKEY *key, const uint8_t *msg, size_t msg_len,
                         const uint8_t *sig, size_t sig_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key);
    int rc = EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(mdctx);
    return rc == 1;
}

#ifdef SC_JNI_BUILD

static jbyteArray JNICALL native_sign(JNIEnv *env, jclass clazz, jstring jdata, jstring jalias, jboolean useEc) {
    (void)clazz;
    size_t data_len;
    uint8_t *data = utf16_to_utf8(env, jdata, &data_len);
    const char *alias = (*env)->GetStringUTFChars(env, jalias, NULL);
    AliasKeys *k = store_get_or_create(alias);
    (*env)->ReleaseStringUTFChars(env, jalias, alias);

    size_t sig_len;
    uint8_t *sig = useEc ? ecdsa_sign(k->ec, data, data_len, &sig_len)
                          : rsa_pss_sign(k->rsa, data, data_len, &sig_len);
    free(data);

    jbyteArray out = (*env)->NewByteArray(env, (jsize)sig_len);
    (*env)->SetByteArrayRegion(env, out, 0, (jsize)sig_len, (jbyte *)sig);
    free(sig);
    return out;
}

static jboolean JNICALL native_verify(JNIEnv *env, jclass clazz, jstring jdata, jstring jsigB64, jobject pubKeyObj) {
    (void)clazz;
    size_t data_len;
    uint8_t *data = utf16_to_utf8(env, jdata, &data_len);

    const char *sig_b64 = (*env)->GetStringUTFChars(env, jsigB64, NULL);
    size_t sig_len;
    uint8_t *sig = b64_decode(sig_b64, strlen(sig_b64), &sig_len);
    (*env)->ReleaseStringUTFChars(env, jsigB64, sig_b64);

    jclass keyClass = (*env)->GetObjectClass(env, pubKeyObj);
    jmethodID getEncoded = (*env)->GetMethodID(env, keyClass, "getEncoded", "()[B");
    jbyteArray encoded = (jbyteArray)(*env)->CallObjectMethod(env, pubKeyObj, getEncoded);
    jsize enc_len = (*env)->GetArrayLength(env, encoded);
    jbyte *enc_bytes = (*env)->GetByteArrayElements(env, encoded, NULL);

    const unsigned char *p = (const unsigned char *)enc_bytes;
    EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, enc_len);
    (*env)->ReleaseByteArrayElements(env, encoded, enc_bytes, JNI_ABORT);

    int ok = 0;
    if (pub) {
        ok = ecdsa_verify(pub, data, data_len, sig, sig_len);
        EVP_PKEY_free(pub);
    }
    free(data);
    free(sig);
    return ok ? JNI_TRUE : JNI_FALSE;
}

#ifdef SC_TEST_HOOKS
static jbyteArray JNICALL test_utf8(JNIEnv *env, jclass clazz, jstring jdata) {
    (void)clazz;
    size_t n;
    uint8_t *buf = utf16_to_utf8(env, jdata, &n);
    jbyteArray out = (*env)->NewByteArray(env, (jsize)n);
    (*env)->SetByteArrayRegion(env, out, 0, (jsize)n, (jbyte *)buf);
    free(buf);
    return out;
}

static jbyteArray JNICALL test_pubkey_der(JNIEnv *env, jclass clazz, jstring jalias, jstring jalgo) {
    (void)clazz;
    const char *alias = (*env)->GetStringUTFChars(env, jalias, NULL);
    const char *algo = (*env)->GetStringUTFChars(env, jalgo, NULL);
    AliasKeys *k = store_get_or_create(alias);
    EVP_PKEY *key = (strcmp(algo, "EC") == 0) ? k->ec : k->rsa;
    (*env)->ReleaseStringUTFChars(env, jalias, alias);
    (*env)->ReleaseStringUTFChars(env, jalgo, algo);

    unsigned char *der = NULL;
    int len = i2d_PUBKEY(key, &der);
    jbyteArray out = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, out, 0, len, (jbyte *)der);
    OPENSSL_free(der);
    return out;
}
#endif

static void JNICALL native_enable(JNIEnv *env, jclass clazz) {
    JNINativeMethod methods[] = {
        {"nOfflineSignWithKey", "(Ljava/lang/String;Ljava/lang/String;Z)[B", (void *)native_sign},
        {"nOfflineVerifyEcSignature", "(Ljava/lang/String;Ljava/lang/String;Ljava/security/PublicKey;)Z", (void *)native_verify},
#ifdef SC_TEST_HOOKS
        {"nTestUtf8", "(Ljava/lang/String;)[B", (void *)test_utf8},
        {"nTestGetPublicKeyDer", "(Ljava/lang/String;Ljava/lang/String;)[B", (void *)test_pubkey_der},
#endif
    };
    (*env)->RegisterNatives(env, clazz, methods, sizeof(methods) / sizeof(methods[0]));
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass clazz = (*env)->FindClass(env, CLS);
    if (!clazz) return JNI_ERR;
    // Two-stage registration matches the real .so: nEnableUPILITEX registers the other two.
    JNINativeMethod method = {"nEnableUPILITEX", "()V", (void *)native_enable};
    if ((*env)->RegisterNatives(env, clazz, &method, 1) != 0) return JNI_ERR;
    return JNI_VERSION_1_6;
}

#elif defined(SC_TEST_MAIN) // exercise the crypto core directly, no JVM required.

int main(void) {
    const char *msg = "5241234567890123|100.00|20260803";
    size_t msg_len = strlen(msg);
    AliasKeys *k = store_get_or_create("NPCI_UPI_LITE_X");

    size_t pss_len;
    uint8_t *pss = rsa_pss_sign(k->rsa, (const uint8_t *)msg, msg_len, &pss_len);
    printf("RSA/PSS sign (useEc=false):  %zu bytes\n", pss_len);

    size_t ec_len;
    uint8_t *ec_sig = ecdsa_sign(k->ec, (const uint8_t *)msg, msg_len, &ec_len);
    printf("ECDSA sign (useEc=true):     %zu bytes\n", ec_len);

    int genuine = ecdsa_verify(k->ec, (const uint8_t *)msg, msg_len, ec_sig, ec_len);
    printf("verify(genuine):             %s\n", genuine ? "true" : "false");

    int tampered = ecdsa_verify(k->ec, (const uint8_t *)"tampered-payload", 17, ec_sig, ec_len);
    printf("verify(tampered, expect 0):  %s\n", tampered ? "true" : "false");

    int cross = ecdsa_verify(k->ec, (const uint8_t *)msg, msg_len, pss, pss_len);
    printf("verify(PSS-sig, expect 0):   %s\n", cross ? "true" : "false");

    const char *b64_known = "aGVsbG8sIHdvcmxkIQ==";
    size_t dec_len;
    uint8_t *dec = b64_decode(b64_known, strlen(b64_known), &dec_len);
    printf("base64 decode roundtrip:     %.*s\n", (int)dec_len, dec);

    free(pss);
    free(ec_sig);
    free(dec);
    return (genuine && !tampered && !cross) ? 0 : 1;
}

#else // SC_STDIO_SERVER -- hex-line protocol over stdin/stdout, no JNI/JVM.

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t *hex_decode(const char *in, size_t *out_len) {
    size_t n = strlen(in) / 2;
    uint8_t *out = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((hexval(in[2 * i]) << 4) | hexval(in[2 * i + 1]));
    }
    *out_len = n;
    return out;
}

static void print_ok_hex(const uint8_t *data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    char *line = malloc(len * 2 + 4);
    memcpy(line, "OK ", 3);
    for (size_t i = 0; i < len; i++) {
        line[3 + 2 * i] = digits[data[i] >> 4];
        line[3 + 2 * i + 1] = digits[data[i] & 0xF];
    }
    line[3 + len * 2] = '\0';
    puts(line);
    fflush(stdout);
    free(line);
}

// Hex-decodes into a nul-terminated C string, truncating to fit rather than overflowing.
static void hex_decode_cstr(const char *in, char *out, size_t out_cap) {
    size_t n;
    uint8_t *raw = hex_decode(in, &n);
    size_t copy = n < out_cap - 1 ? n : out_cap - 1;
    memcpy(out, raw, copy);
    out[copy] = '\0';
    free(raw);
}

// strtok_r drops empty fields between delimiters; split on each space instead so "" survives.
static void split_line(char *line, char *tokens[4]) {
    for (int i = 0; i < 4; i++) tokens[i] = NULL;
    int n = 0;
    char *p = line;
    tokens[n++] = p;
    while (*p && n < 4) {
        if (*p == ' ') {
            *p = '\0';
            tokens[n++] = p + 1;
        }
        p++;
    }
}

int main(void) {
    puts("READY secure_component.c sign,verify,pubkey");
    fflush(stdout);

    static char line[1 << 20];
    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;
        if (strcmp(line, "QUIT") == 0) break;

        char *tokens[4];
        split_line(line, tokens);
        char *op = tokens[0];
        char *arg1 = tokens[1];
        char *arg2 = tokens[2];
        char *arg3 = tokens[3];

        if (op && strcmp(op, "sign") == 0 && arg1 && arg2 && arg3) {
            char alias[256];
            hex_decode_cstr(arg1, alias, sizeof(alias));
            size_t data_len;
            uint8_t *data = hex_decode(arg2, &data_len);
            int useEc = strcmp(arg3, "01") == 0;

            AliasKeys *k = store_get_or_create(alias);
            size_t sig_len;
            uint8_t *sig = useEc ? ecdsa_sign(k->ec, data, data_len, &sig_len)
                                  : rsa_pss_sign(k->rsa, data, data_len, &sig_len);
            print_ok_hex(sig, sig_len);
            free(data);
            free(sig);
        } else if (op && strcmp(op, "verify") == 0 && arg1 && arg2 && arg3) {
            size_t der_len, data_len, sig_len;
            uint8_t *der = hex_decode(arg1, &der_len);
            uint8_t *data = hex_decode(arg2, &data_len);
            uint8_t *sig = hex_decode(arg3, &sig_len);

            const unsigned char *p = der;
            EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, (long)der_len);
            uint8_t result = 0;
            if (pub) {
                result = ecdsa_verify(pub, data, data_len, sig, sig_len) ? 1 : 0;
                EVP_PKEY_free(pub);
            }
            print_ok_hex(&result, 1);
            free(der);
            free(data);
            free(sig);
        } else if (op && strcmp(op, "pubkey") == 0 && arg1 && arg2) {
            char alias[256], algo[16];
            hex_decode_cstr(arg1, alias, sizeof(alias));
            hex_decode_cstr(arg2, algo, sizeof(algo));

            AliasKeys *k = store_get_or_create(alias);
            EVP_PKEY *key = strcmp(algo, "EC") == 0 ? k->ec : k->rsa;
            unsigned char *der = NULL;
            int der_len = i2d_PUBKEY(key, &der);
            print_ok_hex(der, (size_t)der_len);
            OPENSSL_free(der);
        } else {
            printf("ERR bad request\n");
            fflush(stdout);
        }
    }
    return 0;
}

#endif
