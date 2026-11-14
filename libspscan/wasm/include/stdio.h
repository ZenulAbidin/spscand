/* Minimal stdio.h for the freestanding wasm32 build. libsecp256k1 includes it
 * for its default error callbacks and a debug helper. Nothing is
 * printed; abort() (in stdlib.h) traps. */
#ifndef SPSCAN_WASM_STDIO_H
#define SPSCAN_WASM_STDIO_H
#define stderr ((void *)0)
static inline int fprintf(void *stream, const char *format, ...) {
    (void)stream;
    (void)format;
    return 0;
}
static inline int printf(const char *format, ...) {
    (void)format;
    return 0;
}
#endif
