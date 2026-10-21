#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
int IHBTestOneInput(const uint8_t *data, size_t size) {
    (void)data; (void)size;
    for (;;) pause();
}
