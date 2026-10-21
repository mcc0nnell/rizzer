/* Safe synthetic branching target for coverage/corpus tests. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
static volatile unsigned observed;
int IHBTestOneInput(const uint8_t *data, size_t size) {
    if (!size) return 0;
    if (data[0] >= 8) { observed = 9; return 0; }
    if (data[0] == 1) observed = 1;
    else if (data[0] == 2) observed = 2;
    else if (data[0] == 4) observed = 4;
    uint8_t *p = malloc(8);
    if (!p) return 0;
    for (size_t i = 0; i < 8; ++i) p[i] = (uint8_t)i;
    observed = p[data[0]];
    free(p);
    return 0;
}
