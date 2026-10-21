/* Deliberate synthetic integer undefined behavior. */
#include <stddef.h>
#include <stdint.h>
int IHBTestOneInput(const uint8_t *data, size_t size) {
    if (!size) return 0;
    volatile int denominator = data[0];
    volatile int observed = 1 / denominator;
    (void)observed;
    return 0;
}
