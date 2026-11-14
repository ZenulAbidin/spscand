/* The few libc functions libspscan and libsecp256k1 need, for a freestanding
 * wasm32 build with no libc and no imports. Compiled with -fno-builtin so the
 * compiler does not turn these loops back into calls to themselves.
 *
 * malloc is a first-fit allocator over one heap that grows with memory.grow and
 * never shrinks. Each block has a 16-byte header (its size, including the
 * header, and whether it is in use); adjacent free blocks are merged when
 * malloc walks over them. The heap stays small: a scan allocates per call and
 * frees everything before it returns. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ALIGN 16
#define HDR 16
#define PAGE 65536

typedef struct {
    size_t size;
    size_t used;
} block;

extern unsigned char __heap_base;
static uintptr_t heap_lo, heap_top, heap_end;

static int heap_reserve(uintptr_t end) {
    if (end > heap_end) {
        size_t pages = (end - heap_end + PAGE - 1) / PAGE;
        if (__builtin_wasm_memory_grow(0, pages) == (size_t)-1) return 0;
        heap_end = (uintptr_t)__builtin_wasm_memory_size(0) * PAGE;
    }
    return 1;
}

void *malloc(size_t n) {
    uintptr_t p;
    size_t need;
    if (heap_lo == 0) {
        heap_lo = ((uintptr_t)&__heap_base + ALIGN - 1) & ~(uintptr_t)(ALIGN - 1);
        heap_top = heap_lo;
        heap_end = (uintptr_t)__builtin_wasm_memory_size(0) * PAGE;
    }
    if (n > SIZE_MAX / 2) return NULL;
    need = ((n + ALIGN - 1) & ~(size_t)(ALIGN - 1)) + HDR;
    for (p = heap_lo; p < heap_top; p += ((block *)p)->size) {
        block *b = (block *)p;
        if (b->used) continue;
        while (p + b->size < heap_top && !((block *)(p + b->size))->used) {
            b->size += ((block *)(p + b->size))->size;
        }
        if (p + b->size == heap_top) {  /* free space at the top: reuse it below */
            heap_top = p;
            break;
        }
        if (b->size >= need) {
            if (b->size - need >= HDR + ALIGN) {
                block *rest = (block *)(p + need);
                rest->size = b->size - need;
                rest->used = 0;
                b->size = need;
            }
            b->used = 1;
            return (void *)(p + HDR);
        }
    }
    if (need > UINTPTR_MAX - heap_top || !heap_reserve(heap_top + need)) return NULL;
    p = heap_top;
    ((block *)p)->size = need;
    ((block *)p)->used = 1;
    heap_top += need;
    return (void *)(p + HDR);
}

void free(void *ptr) {
    block *b;
    if (ptr == NULL) return;
    b = (block *)((uintptr_t)ptr - HDR);
    b->used = 0;
    if ((uintptr_t)b + b->size == heap_top) heap_top = (uintptr_t)b;
}

void *calloc(size_t count, size_t size) {
    void *p;
    if (size && count > SIZE_MAX / size) return NULL;
    p = malloc(count * size);
    if (p) memset(p, 0, count * size);
    return p;
}

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        while (n--) d[n] = s[n];
    }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    for (; n; n--, x++, y++) {
        if (*x != *y) return *x < *y ? -1 : 1;
    }
    return 0;
}

static void swap(unsigned char *a, unsigned char *b, size_t n) {
    while (n--) {
        unsigned char t = *a;
        *a++ = *b;
        *b++ = t;
    }
}

static void sift(unsigned char *base, size_t root, size_t end, size_t size,
                 int (*cmp)(const void *, const void *)) {
    for (;;) {
        size_t child = 2 * root + 1;
        if (child >= end) return;
        if (child + 1 < end && cmp(base + child * size, base + (child + 1) * size) < 0) child++;
        if (cmp(base + root * size, base + child * size) >= 0) return;
        swap(base + root * size, base + child * size, size);
        root = child;
    }
}

/* Heapsort: not stable, which qsort need not be. */
void qsort(void *base, size_t count, size_t size, int (*cmp)(const void *, const void *)) {
    unsigned char *b = base;
    size_t i, end;
    if (count < 2) return;
    for (i = count / 2; i-- > 0;) sift(b, i, count, size, cmp);
    for (end = count - 1; end > 0; end--) {
        swap(b, b + end * size, size);
        sift(b, 0, end, size, cmp);
    }
}
