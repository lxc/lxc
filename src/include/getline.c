#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Emulate glibc getline() via BSD fgetln().
 * Note that outsize is not changed unless memory is allocated.
 */
ssize_t
getline(char **outbuf, size_t *outsize, FILE *fp)
{
    size_t len;
    char *buf;
    buf = fgetln(fp, &len);

    if (buf == NULL)
        return (-1);

    /* Assumes realloc() accepts NULL for ptr (C99) */
    if (*outbuf == NULL || *outsize < len + 1) {
        void *tmp = realloc(*outbuf, len + 1);
        if (tmp == NULL)
            return (-1);
        *outbuf = tmp;
        *outsize = len + 1;
    }
    memcpy(*outbuf, buf, len);
    (*outbuf)[len] = '\0';
    return (len);
}
