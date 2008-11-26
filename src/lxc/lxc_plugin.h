#ifndef _lxc_plugin_h
#define _lxc_plugin_h

#include <sys/types.h>
 
extern int lxc_plugin_checkpoint(pid_t, const char *, unsigned long);
extern int lxc_plugin_restart(pid_t, const char *, unsigned long);

#endif
