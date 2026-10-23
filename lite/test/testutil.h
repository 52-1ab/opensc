#ifndef LITE_TESTUTIL_H
#define LITE_TESTUTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks = 0;

#define CHECK(cond) do { \
    g_checks++; \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); exit(1); } \
} while (0)

#define CHECK_STR(got, want) do { \
    g_checks++; \
    if (strcmp((got), (want)) != 0) { \
        fprintf(stderr, "FAIL %s:%d: got [%s] want [%s]\n", __FILE__, __LINE__, (got), (want)); \
        exit(1); \
    } \
} while (0)

#define DONE() do { printf("  ok (%d checks)\n", g_checks); return 0; } while (0)

#endif
