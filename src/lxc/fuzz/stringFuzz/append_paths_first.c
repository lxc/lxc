#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/strlcpy.h"
#include "include/strlcat.h"
#include "lxc/string_utils.h"

extern char* LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {

    const char* second = "hello/i/am/testing/path";
    const char* first = (char*)buf;
    lxc_append_paths(first, second);
	return 0;
}