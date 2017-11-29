// These should be organized in a way that makes more sense

// lxc_copy.c: 518; lxc_unshare.c: 248
#define LXC_CLONE_ERR 1 
//lxc_copy.c: 866
#define LXC_FD_ERR 2
//lxc_create.c:127, lxc_init.c: 210; lxc_unshare.c: 134
#define LXC_EXEC_ERR 3
//lxc_create.c:329; lxc_execute.c: 149; lxc_start.c: 215; 246
#define LXC_CREATE_ERR 4
//lxc_destroy.c: 236; lxc_monitor.c: 144; lxc_start.c:234; lxc_top.c: 540, 546
// maybe combined with OOM, idk what else can go wrong with calloc
#define LXC_MEM_ALLOC_ERR 5
//lxc_destroy.c: 243
#define LXC_FILE_READ_ERR 6
//lxc_device.c: 68
#define LXC_FORK_ERR 7
//lxc_device.c: 76
#define LXC_NS_ERR 8
//lxc_device.c: 82
#define LXC_NETIF_ERR 9
//lxc_device.c: 109; lxc_freeze.c: 104; lxc_unfreeze.c: 83
#define LXC_INSUF_PRIV_ERR 10
//lxc_device.c: 135; lxc_freeze.c: 84; lxc_unfreeze.c: 83
#define LXC_CONT_EXIST_ERR 11
//lxc_device.c: 142; lxc_execute.c:156; lxc_freeze.c: 91; lxc_start.c: 220; lxc_unfreeze.c: 96
#define LXC_RCFILE_ERR 12
//lxc_device.c: 147; lxc_execute.c: 162; lxc_freeze.c: 97; lxc_monitor.c: 160; lxc_start.c: 246; lxc_unfreeze.c: 102
#define LXC_OOM_ERR 13
//lxc_device.c: 176, 187
#define LXC_DEVICE_ERR 14
//lxc_device.c: 192; lxc_execute.c: 170; lxc_init.c: 102; lxc_monitor.c: 149, 154; lxc_start.c: 263, 279 285; lxc_unshare.c: 84, 91, 192, 232, 237, 242
#define LXC_ARGS_INVAL 15
//lxc_execute.c: 193
#define LXC_APP_ERR 16
//lxc_freeze.c: 110
#define LXC_FREEZE_ERR 17
//lxc_init.c: 171
#define LXC_SIGACTION_ERR 18
//lxc_init.c: 196, 224
#define LXC_SIGMSK_ERR 19
// lxc_init.c: 274; lxc_unshare.c: 263
#define LXC_WAIT_ERR 20
//lxc_monitor.c: 126, 131
#define LXC_MONITOR_ERR 21
//lxc_snapshot.c:211, 230, 244, 284
#define LXC_SNAPSHOT_ERR 22
//lxc_start.c: 71, 80
#define LXC_PATH_ERR 23
//lxc_start.c: 325
#define LXC_START_ERR 24
//lxc_top.c: 152; 157, 566, 576, 582
#define LXC_TOP_ERR 25
//lxc_top.c: 236, 255, 311
#define LXC_READ_CGROUP_ERR 26
//lxc_unfreeze.c: 109
#define LXC_UNFREEZE_ERR 27
//lxc_unshared.c: 128
#define LXC_UID_ERR 28
//lxc_unshare.c:122
#define LXC_HOSTNAME_ERR 29
