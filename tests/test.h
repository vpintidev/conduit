#ifndef CONDUIT_TEST_H
#define CONDUIT_TEST_H
/*
 * Minimal, zero-dependency test helper for Conduit.
 *
 * One result line per TEST: green [OK] or red [KO]. A failing CHECK prints
 * file:line and (for the typed variants) expected vs actual just above its
 * test's [KO] line; nothing aborts, so one run shows every failure.
 * test_summary() prints the totals and returns the exit code (0 = all passed).
 *
 * Colour is emitted only when stdout is an interactive terminal (isatty) and
 * the NO_COLOR environment variable is unset, so CI logs and redirected output
 * stay free of escape codes.
 *
 *   #include "test.h"
 *   int main(void) {
 *       TEST("header round-trip");
 *       CHECK_EQ_U32(h.connection_id, 0xABCD1234u);
 *       CHECK(h.type == CONDUIT_PKT_DATA);
 *       return test_summary();
 *   }
 */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

static int  tc_tests_run    = 0;
static int  tc_tests_failed = 0;
static int  tc_cur_failed   = 0;
static int  tc_have_current = 0;
static const char *tc_cur_name = "";

/* Colour only on an interactive terminal with NO_COLOR unset (decided once). */
static int tc_color_on(void) {
    static int decided = 0, on = 0;
    if (!decided) {
        on = isatty(fileno(stdout)) && getenv("NO_COLOR") == NULL;
        decided = 1;
    }
    return on;
}
static const char *tc_grn(void) { return tc_color_on() ? "\033[32m" : ""; }
static const char *tc_red(void) { return tc_color_on() ? "\033[31m" : ""; }
static const char *tc_dim(void) { return tc_color_on() ? "\033[2m"  : ""; }
static const char *tc_rst(void) { return tc_color_on() ? "\033[0m"  : ""; }

/* Emit the result line for the test that just finished. */
static void tc_finalize(void) {
    if (!tc_have_current) return;
    if (tc_cur_failed == 0) {
        printf("  %s[OK]%s %s\n", tc_grn(), tc_rst(), tc_cur_name);
    } else {
        printf("  %s[KO]%s %s\n", tc_red(), tc_rst(), tc_cur_name);
        tc_tests_failed++;
    }
}

/* Begin a named test. */
#define TEST(name) do {       \
    tc_finalize();            \
    tc_have_current = 1;      \
    tc_cur_failed   = 0;      \
    tc_cur_name     = (name); \
    tc_tests_run++;           \
} while (0)

/* Generic boolean check. */
#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        tc_cur_failed++;                                          \
        printf("      %sFAIL %s:%d: %s%s\n",                      \
               tc_dim(), __FILE__, __LINE__, #cond, tc_rst());    \
    }                                                             \
} while (0)

/* Equality of unsigned 32-bit values, reported in hex. */
#define CHECK_EQ_U32(got, want) do {                                   \
    uint32_t t_got = (uint32_t)(got), t_want = (uint32_t)(want);       \
    if (t_got != t_want) {                                             \
        tc_cur_failed++;                                               \
        printf("      %sFAIL %s:%d: %s  (expected 0x%08" PRIX32        \
               ", got 0x%08" PRIX32 ")%s\n",                           \
               tc_dim(), __FILE__, __LINE__, #got, t_want, t_got,      \
               tc_rst());                                              \
    }                                                                  \
} while (0)

/* Equality of size_t values, reported in decimal. */
#define CHECK_EQ_SIZE(got, want) do {                                  \
    size_t t_got = (size_t)(got), t_want = (size_t)(want);             \
    if (t_got != t_want) {                                             \
        tc_cur_failed++;                                               \
        printf("      %sFAIL %s:%d: %s  (expected %zu, got %zu)%s\n",  \
               tc_dim(), __FILE__, __LINE__, #got, t_want, t_got,      \
               tc_rst());                                              \
    }                                                                  \
} while (0)

/* Print totals; return 0 if all tests passed, 1 otherwise. */
static int test_summary(void) {
    tc_finalize();
    int passed = tc_tests_run - tc_tests_failed;
    const char *col = (tc_tests_failed == 0) ? tc_grn() : tc_red();
    printf("\n%s%s%s  %d passed, %d failed (%d total)\n",
           col, (tc_tests_failed == 0) ? "PASS" : "FAIL", tc_rst(),
           passed, tc_tests_failed, tc_tests_run);
    return tc_tests_failed == 0 ? 0 : 1;
}

#endif /* CONDUIT_TEST_H */