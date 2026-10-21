/* Child-state and credential-environment control. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
static unsigned calls;
int IHBTestOneInput(const uint8_t *data, size_t size) {
    (void)data; (void)size;
    if (getenv("IHB_FUZZ_TEST_SECRET")) return 1;
    return ++calls == 1 ? 0 : 1;
}
