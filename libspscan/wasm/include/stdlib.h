/* Minimal stdlib.h for the freestanding wasm32 build (see ../libc.c). */
#ifndef SPSCAN_WASM_STDLIB_H
#define SPSCAN_WASM_STDLIB_H
#include <stddef.h>

void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void free(void *ptr);
void qsort(void *base, size_t count, size_t size, int (*cmp)(const void *, const void *));
#define abort() __builtin_trap()

#endif
