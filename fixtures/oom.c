/* Deliberately exhaust a bounded container's cgroup memory; synthetic only. */
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
int IHBTestOneInput(const uint8_t *data, size_t size) {
    (void)data; (void)size;
    const size_t bytes = 1024ULL * 1024ULL * 1024ULL;
    volatile unsigned char *p = mmap(0, bytes, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 90;
    for (size_t i = 0; i < bytes; i += 4096) p[i] = (unsigned char)(i >> 12);
    munmap((void *)p, bytes);
    return 0;
}
