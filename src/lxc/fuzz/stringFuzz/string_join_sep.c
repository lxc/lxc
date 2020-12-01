#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/strlcpy.h"
#include "include/strlcat.h"
#include "lxc/string_utils.h"

extern char* LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
	const char *parts[3] = {0};
    parts[0] = "hello";
    parts[1] = "world";
 
	bool pre = 1;

    lxc_string_join((char*)buf, parts, pre);
	return 0;
}