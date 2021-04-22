/* SPDX-License-Identifier: LGPL-2.1+ */


#include <stdlib.h>
#include <string.h>

#include "config.h"

#ifndef HAVE_STRCHRNUL
#include "../../../include/strchrnul.h"
#endif

/* Parse comma separated suboption from *OPTIONP and match against
   strings in TOKENS.  If found return index and set *VALUEP to
   optional value introduced by an equal sign.  If the suboption is
   not part of TOKENS return in *VALUEP beginning of unknown
   suboption.  On exit *OPTIONP is set to the beginning of the next
   token or at the terminating NUL character.  */
int
getsubopt (char **optionp, char *const *tokens, char **valuep)
{
  char *endp, *vstart;
  int cnt;

  if (**optionp == '\0')
    return -1;

  /* Find end of next token.  */
  endp = strchrnul (*optionp, ',');

  /* Find start of value.  */
  vstart = memchr (*optionp, '=', endp - *optionp);
  if (vstart == NULL)
    vstart = endp;

  /* Try to match the characters between *OPTIONP and VSTART against
     one of the TOKENS.  */
  for (cnt = 0; tokens[cnt] != NULL; ++cnt)
    if (strncmp (*optionp, tokens[cnt], vstart - *optionp) == 0
    && tokens[cnt][vstart - *optionp] == '\0')
      {
    /* We found the current option in TOKENS.  */
    *valuep = vstart != endp ? vstart + 1 : NULL;

    if (*endp != '\0')
      *endp++ = '\0';
    *optionp = endp;

    return cnt;
      }

  /* The current suboption does not match any option.  */
  *valuep = *optionp;

  if (*endp != '\0')
    *endp++ = '\0';
  *optionp = endp;

  return -1;
}
