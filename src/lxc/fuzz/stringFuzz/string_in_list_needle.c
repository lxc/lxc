#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/strlcpy.h"
#include "include/strlcat.h"
#include "lxc/string_utils.h"

extern char* LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {

    const char* haystack = "hello i ,am, testing, string";
    const char* needle = (char*)buf;
    lxc_string_in_list(needle, haystack, ",");
	return 0;
}