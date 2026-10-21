/* Synthetic out-of-bounds heap read. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
int IHBTestOneInput(const uint8_t *data, size_t size) {
    if (!size) return 0;
    uint8_t *p = malloc(8);
    if (!p) return 0;
    for (size_t i = 0; i < 8; ++i) p[i] = (uint8_t)i;
    volatile uint8_t observed = p[data[0]];
    (void)observed;
    free(p);
    return 0;
}
