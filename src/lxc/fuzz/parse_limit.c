#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "lxc/macro.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
    
    rlim_t temp = 0;
    rlim_t* res = &temp;
    char** value = (char**)buf;
    
    char *endptr = NULL;

	if (strncmp(*value, "unlimited", STRLITERALLEN("unlimited")) == 0) {
		*res = RLIM_INFINITY;
		*value += STRLITERALLEN("unlimited");
		return 0;
	}

	int errno = 0;
	*res = strtoull(*value, &endptr, 10);
	if (errno || !endptr)
		return 0;

	*value = endptr;

	return 0;
}