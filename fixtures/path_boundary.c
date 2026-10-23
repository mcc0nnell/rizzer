/*
 * SPDX-License-Identifier: Apache-2.0
 * Synthetic path-component policy for Rizzer. Does no filesystem I/O.
 * This is NOT an implementation of Windows filesystem semantics.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define RZ_MAX_COMPONENT 64u
#define RZ_ROOT "/synthetic/recovery"
#define RZ_FILE "record.bin"

static int rz_same_ascii_fold(const uint8_t *s, size_t n, const char *word) {
    size_t j;
    if (strlen(word) != n) return 0;
    for (j = 0; j < n; ++j) {
        uint8_t a = s[j], b = (uint8_t)word[j];
        if (a >= (uint8_t)'a' && a <= (uint8_t)'z') a = (uint8_t)(a - 32);
        if (b >= (uint8_t)'a' && b <= (uint8_t)'z') b = (uint8_t)(b - 32);
        if (a != b) return 0;
    }
    return 1;
}
static int rz_reserved_device(const uint8_t *s, size_t length) {
    size_t stem = 0;
    while (stem < length && s[stem] != (uint8_t)'.') ++stem;
    if (rz_same_ascii_fold(s, stem, "CON") ||
        rz_same_ascii_fold(s, stem, "PRN") ||
        rz_same_ascii_fold(s, stem, "AUX") ||
        rz_same_ascii_fold(s, stem, "NUL")) return 1;
    /* Conservative Windows device-name check, including COM0 and LPT0. */
    if (stem == 4 && s[3] >= (uint8_t)'0' && s[3] <= (uint8_t)'9' &&
        (rz_same_ascii_fold(s, 3, "COM") ||
         rz_same_ascii_fold(s, 3, "LPT"))) return 1;
    return 0;
}
/* Returns 1 only for one bounded, opaque ASCII component. */
int rz_validate_component(const uint8_t *data, size_t size) {
    size_t i;
    if (data == NULL || size == 0 || size > RZ_MAX_COMPONENT) return 0;
    if (data[0] == (uint8_t)'.' || data[size - 1] == (uint8_t)'.') return 0;
    for (i = 0; i < size; ++i) {
        const uint8_t c = data[i];
        const int permitted = (c >= (uint8_t)'A' && c <= (uint8_t)'Z') ||
            (c >= (uint8_t)'a' && c <= (uint8_t)'z') ||
            (c >= (uint8_t)'0' && c <= (uint8_t)'9') ||
            c == (uint8_t)'_' || c == (uint8_t)'-' || c == (uint8_t)'.';
        if (!permitted) return 0;
        if (c == (uint8_t)'.' && i > 0 && data[i - 1] == (uint8_t)'.')
            return 0;
    }
    if (rz_reserved_device(data, size)) return 0;
    return 1;
}
/* Pure builder: no open, mkdir, rename, shell, network, or actual paths. */
int rz_build_destination(const uint8_t *data, size_t size,
                         char *out, size_t capacity) {
    const size_t rootlen = sizeof(RZ_ROOT) - 1;
    const size_t filelen = sizeof(RZ_FILE) - 1;
    size_t required;
    if (!rz_validate_component(data, size)) return 0;
    required = rootlen + 1 + size + 1 + filelen + 1;
    if (out == NULL || capacity < required) return 0;
    memcpy(out, RZ_ROOT, rootlen);
    out[rootlen] = '/';
    memcpy(out + rootlen + 1, data, size);
    out[rootlen + 1 + size] = '/';
    memcpy(out + rootlen + 1 + size + 1, RZ_FILE, filelen);
    out[required - 1] = '\0';
    return 1;
}
/* Native fuzzer ABI: any policy-property violation is a candidate crash. */
int IHBTestOneInput(const uint8_t *data, size_t size) {
    char destination[sizeof(RZ_ROOT) + RZ_MAX_COMPONENT + sizeof(RZ_FILE) + 2];
    const size_t rootlen = sizeof(RZ_ROOT) - 1;
    const size_t filelen = sizeof(RZ_FILE) - 1;
    const int valid = rz_validate_component(data, size);
    const int built = rz_build_destination(data, size, destination,
                                          sizeof(destination));
    size_t i;
    if (built != valid) __builtin_trap();
    if (!built) return 0;
    if (memcmp(destination, RZ_ROOT, rootlen) != 0 ||
        destination[rootlen] != '/' ||
        memcmp(destination + rootlen + 1, data, size) != 0 ||
        destination[rootlen + size + 1] != '/' ||
        memcmp(destination + rootlen + size + 2, RZ_FILE, filelen) != 0 ||
        destination[rootlen + size + 2 + filelen] != '\0')
        __builtin_trap();
    for (i = 0; i < size; ++i) {
        if (data[i] == '/' || data[i] == '\\' || data[i] == ':')
            __builtin_trap();
    }
    return 0;
}
