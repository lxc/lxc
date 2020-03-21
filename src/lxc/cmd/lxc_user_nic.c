/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "compiler.h"
#include "config.h"
#include "file_utils.h"
#include "log.h"
#include "memory_utils.h"
#include "network.h"
#include "parse.h"
#include "raw_syscalls.h"
#include "string_utils.h"
#include "syscall_wrappers.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#define usernic_debug_stream(stream, format, ...)                              \
	do {                                                                   \
		fprintf(stream, "%s: %d: %s: " format, __FILE__, __LINE__,     \
			__func__, __VA_ARGS__);                                \
	} while (false)

#define usernic_error(format, ...) usernic_debug_stream(stderr, format, __VA_ARGS__)

#define cmd_error_errno(__ret__, __errno__, format, ...)      \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		errno = (__errno__);                          \
		CMD_SYSERROR(format, ##__VA_ARGS__);          \
		__internal_ret__;                             \
	})

__noreturn static void usage(bool fail)
{
	fprintf(stderr, "Description:\n");
	fprintf(stderr, "  Manage nics in another network namespace\n\n");

	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  lxc-user-nic [command]\n\n");

	fprintf(stderr, "Available Commands:\n");
	fprintf(stderr, "  create {lxcpath} {name} {pid} {type} {bridge} {container nicname}\n");
	fprintf(stderr, "  delete {lxcpath} {name} {/proc/<pid>/ns/net} {type} {bridge} {container nicname}\n");

	if (fail)
		_exit(EXIT_FAILURE);

	_exit(EXIT_SUCCESS);
}

static int open_and_lock(const char *path)
{
	__do_close int fd = -EBADF;
	int ret;
	struct flock lk;

	fd = open(path, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR | O_CLOEXEC);
	if (fd < 0) {
		CMD_SYSERROR("Failed to open \"%s\"\n", path);
		return -1;
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;

	ret = fcntl(fd, F_SETLKW, &lk);
	if (ret < 0) {
		CMD_SYSERROR("Failed to lock \"%s\"\n", path);
		return -1;
	}

	return move_fd(fd);
}

static char *get_username(void)
{
	__do_free char *buf = NULL;
	struct passwd pwent;
	struct passwd *pwentp = NULL;
	size_t bufsize;
	int ret;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 1024;

	buf = malloc(bufsize);
	if (!buf)
		return NULL;

	ret = getpwuid_r(getuid(), &pwent, buf, bufsize, &pwentp);
	if (!pwentp) {
		if (ret == 0)
			usernic_error("%s", "Could not find matched password record\n");

		CMD_SYSERROR("Failed to get username: %u\n", getuid());
		return NULL;
	}

	return strdup(pwent.pw_name);
}

static void free_groupnames(char **groupnames)
{
	int i;

	if (!groupnames)
		return;

	for (i = 0; groupnames[i]; i++)
		free(groupnames[i]);

	free(groupnames);
}

static char **get_groupnames(void)
{
	__do_free char *buf = NULL;
	__do_free gid_t *group_ids = NULL;
	int ngroups;
	int ret, i;
	char **groupnames;
	struct group grent;
	struct group *grentp = NULL;
	size_t bufsize;

	ngroups = getgroups(0, NULL);
	if (ngroups < 0) {
		CMD_SYSERROR("Failed to get number of groups the user belongs to\n");
		return NULL;
	} else if (ngroups == 0) {
		return NULL;
	}

	group_ids = malloc(sizeof(gid_t) * ngroups);
	if (!group_ids) {
		CMD_SYSERROR("Failed to allocate memory while getting groups the user belongs to\n");
		return NULL;
	}

	ret = getgroups(ngroups, group_ids);
	if (ret < 0) {
		CMD_SYSERROR("Failed to get process groups\n");
		return NULL;
	}

	groupnames = malloc(sizeof(char *) * (ngroups + 1));
	if (!groupnames) {
		CMD_SYSERROR("Failed to allocate memory while getting group names\n");
		return NULL;
	}

	memset(groupnames, 0, sizeof(char *) * (ngroups + 1));

	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 1024;

	buf = malloc(bufsize);
	if (!buf) {
		free_groupnames(groupnames);
		CMD_SYSERROR("Failed to allocate memory while getting group names\n");
		return NULL;
	}

	for (i = 0; i < ngroups; i++) {
		while ((ret = getgrgid_r(group_ids[i], &grent, buf, bufsize, &grentp)) == ERANGE) {
			bufsize <<= 1;
			if (bufsize > MAX_GRBUF_SIZE) {
				usernic_error("Failed to get group members: %u\n",
				      group_ids[i]);
				free(buf);
				free(group_ids);
				free_groupnames(groupnames);
				return NULL;
			}
			char *new_buf = realloc(buf, bufsize);
			if (!new_buf) {
				usernic_error("Failed to allocate memory while getting group "
					      "names: %s\n",
					      strerror(errno));
				free(buf);
				free(group_ids);
				free_groupnames(groupnames);
				return NULL;
			}
			buf = new_buf;
		}
		if (!grentp) {
			if (ret == 0)
				usernic_error("%s", "Could not find matched group record\n");

			CMD_SYSERROR("Failed to get group name: %u\n", group_ids[i]);
			free_groupnames(groupnames);
			return NULL;
		}

		groupnames[i] = strdup(grent.gr_name);
		if (!groupnames[i]) {
			usernic_error("Failed to copy group name \"%s\"", grent.gr_name);
			free_groupnames(groupnames);
			return NULL;
		}
	}

	return groupnames;
}

static bool name_is_in_groupnames(char *name, char **groupnames)
{
	while (groupnames) {
		if (!strcmp(name, *groupnames))
			return true;
		groupnames++;
	}

	return false;
}

struct alloted_s {
	char *name;
	int allowed;
	struct alloted_s *next;
};

static struct alloted_s *append_alloted(struct alloted_s **head, char *name,
					int n)
{
	struct alloted_s *cur, *al;

	if (!head || !name) {
		/* Sanity check. Parameters should not be null. */
		usernic_error("%s\n", "Unexpected NULL argument");
		return NULL;
	}

	al = malloc(sizeof(struct alloted_s));
	if (!al) {
		CMD_SYSERROR("Failed to allocate memory\n");
		return NULL;
	}

	al->name = strdup(name);
	if (!al->name) {
		free(al);
		return NULL;
	}

	al->allowed = n;
	al->next = NULL;

	if (!*head) {
		*head = al;
		return al;
	}

	cur = *head;
	while (cur->next)
		cur = cur->next;
	cur->next = al;

	return al;
}

static void free_alloted(struct alloted_s **head)
{
	struct alloted_s *cur;

	if (!head)
		return;

	cur = *head;
	while (cur) {
		cur = cur->next;
		free((*head)->name);
		free(*head);
		*head = cur;
	}
}

/* The configuration file consists of lines of the form:
 *
 * user type bridge count
 * or
 * @group type bridge count
 *
 * Return the count entry for the calling user if there is one.  Else
 * return -1.
 */
static int get_alloted(char *me, char *intype, char *link,
		       struct alloted_s **alloted)
{
	__do_free char *line = NULL;
	__do_fclose FILE *fin = NULL;
	int n, ret;
	char name[100], type[100], br[100];
	char **groups;
	int count = 0;
	size_t len = 0;

	fin = fopen(LXC_USERNIC_CONF, "re");
	if (!fin) {
		CMD_SYSERROR("Failed to open \"%s\"\n", LXC_USERNIC_CONF);
		return -1;
	}

	groups = get_groupnames();
	while ((getline(&line, &len, fin)) != -1) {
		ret = sscanf(line, "%99[^ \t] %99[^ \t] %99[^ \t] %d", name,
			     type, br, &n);
		if (ret != 4)
			continue;

		if (strlen(name) == 0)
			continue;

		if (strcmp(name, me)) {
			if (name[0] != '@')
				continue;

			if (!name_is_in_groupnames(name + 1, groups))
				continue;
		}

		if (strcmp(type, intype))
			continue;

		if (strcmp(link, br))
			continue;

		/* Found the user or group with the appropriate settings,
		 * therefore finish the search. What to do if there are more
		 * than one applicable lines? not specified in the docs. Since
		 * getline is implemented with realloc, we don't need to free
		 * line until exiting func.
		 *
		 * If append_alloted returns NULL, e.g. due to a malloc error,
		 * we set count to 0 and break the loop, allowing cleanup and
		 * then exiting from main().
		 */
		if (!append_alloted(alloted, name, n)) {
			count = 0;
			break;
		}

		count += n;
	}

	free_groupnames(groups);

	/* Now return the total number of nics that this user can create. */
	return count;
}

static char *get_eol(char *s, char *e)
{
	while ((s < e) && *s && (*s != '\n'))
		s++;

	return s;
}

static char *get_eow(char *s, char *e)
{
	while ((s < e) && *s && !isblank(*s) && (*s != '\n'))
		s++;

	return s;
}

static char *find_line(char *buf_start, char *buf_end, char *name,
		       char *net_type, char *net_link, char *net_dev,
		       bool *owner, bool *found, bool *keep)
{
	char *end_of_line, *end_of_word, *line;

	while (buf_start < buf_end) {
		size_t len;
		char netdev_name[IFNAMSIZ];

		*found = false;
		*keep = true;
		*owner = false;

		end_of_line = get_eol(buf_start, buf_end);
		if (end_of_line >= buf_end)
			return NULL;

		line = buf_start;
		if (*buf_start == '#')
			goto next;

		while ((buf_start < buf_end) && isblank(*buf_start))
			buf_start++;

		/* Check whether the line contains the caller's name. */
		end_of_word = get_eow(buf_start, buf_end);
		/* corrupt db */
		if (!end_of_word)
			return NULL;

		if (strncmp(buf_start, name, strlen(name)))
			*found = false;
		else
			if (strlen(name) == (size_t)(end_of_word - buf_start))
				*owner = true;

		buf_start = end_of_word + 1;
		while ((buf_start < buf_end) && isblank(*buf_start))
			buf_start++;

		/* Check whether line is of the right network type. */
		end_of_word = get_eow(buf_start, buf_end);
		/* corrupt db */
		if (!end_of_word)
			return NULL;

		if (strncmp(buf_start, net_type, strlen(net_type)))
			*found = false;

		buf_start = end_of_word + 1;
		while ((buf_start < buf_end) && isblank(*buf_start))
			buf_start++;

		/* Check whether line is contains the right link. */
		end_of_word = get_eow(buf_start, buf_end);
		/* corrupt db */
		if (!end_of_word)
			return NULL;

		if (strncmp(buf_start, net_link, strlen(net_link)))
			*found = false;

		buf_start = end_of_word + 1;
		while ((buf_start < buf_end) && isblank(*buf_start))
			buf_start++;

		/* Check whether line contains the right network device. */
		end_of_word = get_eow(buf_start, buf_end);
		/* corrupt db */
		if (!end_of_word)
			return NULL;

		len = end_of_word - buf_start;
		/* corrupt db */
		if (len >= IFNAMSIZ)
			return NULL;

		memcpy(netdev_name, buf_start, len);
		netdev_name[len] = '\0';
		*keep = lxc_nic_exists(netdev_name);

		if (net_dev && !strcmp(netdev_name, net_dev))
			*found = true;

		return line;

	next:
		buf_start = end_of_line + 1;
	}

	return NULL;
}

static int instantiate_veth(char *veth1, char *veth2, pid_t pid, unsigned int mtu)
{
	int ret;

	ret = lxc_veth_create(veth1, veth2, pid, mtu);
	if (ret < 0) {
		CMD_SYSERROR("Failed to create %s-%s\n", veth1, veth2);
		return ret_errno(-ret);
	}

	/*
	 * Changing the high byte of the mac address to 0xfe, the bridge
	 * interface will always keep the host's mac address and not take the
	 * mac address of a container.
	 */
	ret = setup_private_host_hw_addr(veth1);
	if (ret < 0) {
		CMD_SYSERROR("Failed to change mac address of host interface %s\n", veth1);
		return ret_errno(-ret);
	}

	return netdev_set_flag(veth1, IFF_UP);
}

static int get_mtu(char *name)
{
	int idx;

	idx = if_nametoindex(name);
	if (idx < 0)
		return -1;

	return netdev_get_mtu(idx);
}

static int create_nic(char *nic, char *br, int pid, char **cnic)
{
	unsigned int mtu = 1500;
	int ret;
	char veth1buf[IFNAMSIZ], veth2buf[IFNAMSIZ];

	ret = snprintf(veth1buf, IFNAMSIZ, "%s", nic);
	if (ret < 0 || ret >= IFNAMSIZ) {
		usernic_error("%s", "Could not create nic name\n");
		return -1;
	}

	ret = snprintf(veth2buf, IFNAMSIZ, "%sp", veth1buf);
	if (ret < 0 || ret >= IFNAMSIZ) {
		usernic_error("%s\n", "Could not create nic name");
		return -1;
	}

	if (strcmp(br, "none"))
		mtu = get_mtu(br);
	if (!mtu)
		mtu = 1500;

	/* create the nics */
	ret = instantiate_veth(veth1buf, veth2buf, pid, mtu);
	if (ret < 0) {
		usernic_error("%s", "Error creating veth tunnel\n");
		return -1;
	}

	if (strcmp(br, "none")) {
		if (mtu > 0) {
			ret = lxc_netdev_set_mtu(veth1buf, mtu);
			if (ret < 0) {
				usernic_error("Failed to set mtu to %d on %s\n",
					      mtu, veth1buf);
				goto out_del;
			}
		}

		/* attach veth1 to bridge */
		ret = lxc_bridge_attach(br, veth1buf);
		if (ret < 0) {
			usernic_error("Error attaching %s to %s\n", veth1buf, br);
			goto out_del;
		}
	}

	*cnic = strdup(veth2buf);
	if (!*cnic) {
		usernic_error("Failed to copy string \"%s\"\n", veth2buf);
		return -1;
	}

	return 0;

out_del:
	lxc_netdev_delete_by_name(veth1buf);
	return -1;
}

struct entry_line {
	char *start;
	int len;
	bool keep;
};

static bool cull_entries(int fd, char *name, char *net_type, char *net_link,
			 char *net_dev, bool *found_nicname)
{
	__do_free char *buf = NULL;
	__do_free struct entry_line *entry_lines = NULL;
	int n = 0;
	size_t length = 0;
	int ret;
	char *buf_end, *buf_start;
	bool found, keep;

	ret = fd_to_buf(fd, &buf, &length);
	if (ret < 0) {
		CMD_SYSERROR("Failed to read database file\n");
		return false;
	}
	if (lseek(fd, 0, SEEK_SET) < 0)
		return false;

	if (length == 0)
		return false;

	buf_start = buf;
	buf_end = buf + length;
	while ((buf_start = find_line(buf_start, buf_end, name, net_type,
				      net_link, net_dev, &(bool){true}, &found,
				      &keep))) {
		struct entry_line *newe;

		newe = realloc(entry_lines, sizeof(*entry_lines) * (n + 1));
		if (!newe)
			return false;

		if (found)
			*found_nicname = true;

		entry_lines = newe;
		entry_lines[n].start = buf_start;
		entry_lines[n].len = get_eol(buf_start, buf_end) - entry_lines[n].start;
		entry_lines[n].keep = keep;
		n++;

		buf_start += entry_lines[n - 1].len + 1;
		if (buf_start >= buf_end)
			break;
	}

	buf_start = buf;

	for (int i = 0; i < n; i++) {
		if (!entry_lines[i].keep)
			continue;

		memcpy(buf_start, entry_lines[i].start, entry_lines[i].len);
		buf_start += entry_lines[i].len;
		*buf_start = '\n';
		buf_start++;
	}

	return ftruncate(fd, buf_start - buf) == 0;
}

static int count_entries(char *buf, off_t len, char *name, char *net_type, char *net_link)
{
	int count = 0;
	bool owner = false;
	char *buf_end;

	buf_end = &buf[len];
	while ((buf = find_line(buf, buf_end, name, net_type, net_link, NULL,
				&owner, &(bool){true}, &(bool){true}))) {
		if (owner)
			count++;

		buf = get_eol(buf, buf_end) + 1;
		if (buf >= buf_end)
			break;
	}

	return count;
}

/* The dbfile has lines of the format: user type bridge nicname. */
static char *get_nic_if_avail(int fd, struct alloted_s *names, int pid,
			      char *intype, char *br, int allowed, char **cnic)
{
	__do_free char *buf = NULL, *newline = NULL;
	size_t length = 0;
	int ret;
	size_t slen;
	char *owner;
	char nicname[IFNAMSIZ];
	struct alloted_s *n;
	uid_t uid;

	for (n = names; n != NULL; n = n->next)
		cull_entries(fd, n->name, intype, br, NULL, NULL);

	if (allowed == 0)
		return NULL;

	owner = names->name;

	ret = fd_to_buf(fd, &buf, &length);
	if (ret < 0) {
		CMD_SYSERROR("Failed to read database file\n");
		return false;
	}
	if (lseek(fd, 0, SEEK_SET) < 0)
		return false;

	if (length > 0) {
		owner = NULL;

		for (n = names; n != NULL; n = n->next) {
			int count;

			count = count_entries(buf, length, n->name, intype, br);
			if (count >= n->allowed)
				continue;

			owner = n->name;
			break;
		}
	}

	if (!owner)
		return NULL;

        uid = getuid();
	/*
	 * For POSIX integer uids the network device name schema is
	 * vethUID_XXXX.
	 * With four random characters passed to
	 * lxc_ifname_alnum_case_sensitive() we get 62^4 = 14776336
	 * combinations per uid. That's plenty of network devices for now.
	 */
	if (uid > 0 && uid <= 65536)
		ret = snprintf(nicname, sizeof(nicname), "veth%d_XXXX", uid);
	else
		ret = snprintf(nicname, sizeof(nicname), "vethXXXXXX");
	if (ret < 0 || (size_t)ret >= sizeof(nicname))
		return NULL;

	if (!lxc_ifname_alnum_case_sensitive(nicname))
		return NULL;

	ret = create_nic(nicname, br, pid, cnic);
	if (ret < 0) {
		usernic_error("%s", "Failed to create new nic\n");
		return NULL;
	}

	/* strlen(owner)
	 * +
	 * " "
	 * +
	 * strlen(intype)
	 * +
	 * " "
	 * +
	 * strlen(br)
	 * +
	 * " "
	 * +
	 * strlen(nicname)
	 * +
	 * \n
	 * +
	 * \0
	 */
	slen = strlen(owner) + strlen(intype) + strlen(br) + strlen(nicname) + 4;
	newline = malloc(slen + 1);
	if (!newline) {
		CMD_SYSERROR("Failed allocate memory\n");
		return NULL;
	}

	ret = snprintf(newline, slen + 1, "%s %s %s %s\n", owner, intype, br, nicname);
	if (ret < 0 || (size_t)ret >= (slen + 1)) {
		if (lxc_netdev_delete_by_name(nicname) != 0)
			usernic_error("Error unlinking %s\n", nicname);

		return NULL;
	}

	if (lxc_pwrite_nointr(fd, newline, slen, length) != slen) {
		CMD_SYSERROR("Failed to append new entry \"%s\" to database file", newline);

		if (lxc_netdev_delete_by_name(nicname) != 0)
			usernic_error("Error unlinking %s\n", nicname);

		return NULL;
	}

	ret = ftruncate(fd, length + slen);
	if (ret < 0) {
		CMD_SYSERROR("Failed to truncate file\n");

		if (lxc_netdev_delete_by_name(nicname) != 0)
			usernic_error("Error unlinking %s\n", nicname);

		return NULL;
	}

	return strdup(nicname);
}

static bool create_db_dir(char *fnam)
{
	__do_free char *copy = NULL;
	char *p;
	int ret;

	copy = must_copy_string(fnam);
	p = copy;
	fnam = p;
	p = p + 1;

again:
	while (*p && *p != '/')
		p++;

	if (!*p)
		return true;

	*p = '\0';

	ret = mkdir(fnam, 0755);
	if (ret < 0 && errno != EEXIST) {
		CMD_SYSERROR("Failed to create %s\n", fnam);
		*p = '/';
		return false;
	}

	*(p++) = '/';

	goto again;
}

static char *lxc_secure_rename_in_ns(int pid, char *oldname, char *newname,
				     int *container_veth_ifidx)
{
	__do_close int fd = -EBADF, ofd = -EBADF;
	int fret = -1;
	int ifindex, ret;
	pid_t pid_self;
	uid_t ruid, suid, euid;
	char ifname[IFNAMSIZ];

	pid_self = lxc_raw_getpid();

	ofd = lxc_preserve_ns(pid_self, "net");
	if (ofd < 0)
		return cmd_error_errno(NULL, errno, "Failed opening network namespace path for %d", pid_self);

	fd = lxc_preserve_ns(pid, "net");
	if (fd < 0)
		return cmd_error_errno(NULL, errno, "Failed opening network namespace path for %d", pid);

	ret = getresuid(&ruid, &euid, &suid);
	if (ret < 0)
		return cmd_error_errno(NULL, errno, "Failed to retrieve real, effective, and saved user IDs\n");

	ret = setns(fd, CLONE_NEWNET);
	if (ret < 0)
		return cmd_error_errno(NULL, errno, "Failed to setns() to the network namespace of the container with PID %d\n", pid);

	ret = setresuid(ruid, ruid, 0);
	if (ret < 0) {
		CMD_SYSERROR("Failed to drop privilege by setting effective user id and real user id to %d, and saved user ID to 0\n", ruid);
		/*
		 * It's ok to jump to do_full_cleanup here since setresuid()
		 * will succeed when trying to set real, effective, and saved
		 * to values they currently have.
		 */
		goto out_setns;
	}

	/* Check if old interface exists. */
	ifindex = if_nametoindex(oldname);
	if (!ifindex) {
		CMD_SYSERROR("Failed to get netdev index\n");
		goto out_setresuid;
	}

	/*
	 * When the IFLA_IFNAME attribute is passed something like "<prefix>%d"
	 * netlink will replace the format specifier with an appropriate index.
	 * So we pass "eth%d".
	 */
	ret = lxc_netdev_rename_by_name(oldname, newname ? newname : "eth%d");
	if (ret < 0) {
		CMD_SYSERROR("Error %d renaming netdev %s to %s in container\n", ret, oldname, newname ? newname : "eth%d");
		goto out_setresuid;
	}

	/* Retrieve new name for interface. */
	if (!if_indextoname(ifindex, ifname)) {
		CMD_SYSERROR("Failed to get new netdev name\n");
		goto out_setresuid;
	}

	fret = 0;

out_setresuid:
	ret = setresuid(ruid, euid, suid);
	if (ret < 0)
		return cmd_error_errno(NULL, errno, "Failed to restore privilege by setting effective user id to %d, real user id to %d, and saved user ID to %d\n",
				       ruid, euid, suid);

out_setns:
	ret = setns(ofd, CLONE_NEWNET);
	if (ret < 0)
		return cmd_error_errno(NULL, errno, "Failed to setns() to original network namespace of PID %d\n", ofd);

	if (fret < 0)
		return NULL;

	*container_veth_ifidx = ifindex;
	return strdup(ifname);
}

/* If the caller (real uid, not effective uid) may read the /proc/[pid]/ns/net,
 * then it is either the caller's netns or one which it created.
 */
static bool may_access_netns(int pid)
{
	int ret;
	char s[200];
	uid_t ruid, suid, euid;
	bool may_access = false;

	ret = getresuid(&ruid, &euid, &suid);
	if (ret < 0) {
		CMD_SYSERROR("Failed to retrieve real, effective, and saved user IDs\n");
		return false;
	}

	ret = setresuid(ruid, ruid, euid);
	if (ret < 0) {
		CMD_SYSERROR("Failed to drop privilege by setting effective user id and real user id to %d, and saved user ID to %d\n",
			     ruid, euid);
		return false;
	}

	ret = snprintf(s, 200, "/proc/%d/ns/net", pid);
	if (ret < 0 || ret >= 200)
		return false;

	ret = access(s, R_OK);
	may_access = true;
	if (ret < 0) {
		may_access = false;
		CMD_SYSERROR("Uid %d may not access %s\n", (int)ruid, s);
	}

	ret = setresuid(ruid, euid, suid);
	if (ret < 0) {
		CMD_SYSERROR("Failed to restore user id to %d, real user id to %d, and saved user ID to %d\n",
			     ruid, euid, suid);
		may_access = false;
	}

	return may_access;
}

struct user_nic_args {
	char *cmd;
	char *lxc_path;
	char *lxc_name;
	char *pid;
	char *type;
	char *link;
	char *veth_name;
};

enum lxc_user_nic_command {
	LXC_USERNIC_CREATE = 0,
	LXC_USERNIC_DELETE = 1,
};

static bool is_privileged_over_netns(int netns_fd)
{
	int ofd, ret;
	pid_t pid_self;
	uid_t euid, ruid, suid;
	bool bret = false;

	pid_self = lxc_raw_getpid();

	ofd = lxc_preserve_ns(pid_self, "net");
	if (ofd < 0) {
		usernic_error("Failed opening network namespace path for %d", pid_self);
		return false;
	}

	ret = getresuid(&ruid, &euid, &suid);
	if (ret < 0) {
		CMD_SYSERROR("Failed to retrieve real, effective, and saved user IDs\n");
		goto do_partial_cleanup;
	}

	ret = setns(netns_fd, CLONE_NEWNET);
	if (ret < 0) {
		CMD_SYSERROR("Failed to setns() to network namespace\n");
		goto do_partial_cleanup;
	}

	ret = setresuid(ruid, ruid, 0);
	if (ret < 0) {
		CMD_SYSERROR("Failed to drop privilege by setting effective user id and real user id to %d, and saved user ID to 0\n",
			     ruid);
		/* It's ok to jump to do_full_cleanup here since setresuid()
		 * will succeed when trying to set real, effective, and saved to
		 * values they currently have.
		 */
		goto do_full_cleanup;
	}

	/* Test whether we are privileged over the network namespace. To do this
	 * we try to delete the loopback interface which is not possible. If we
	 * are privileged over the network namespace we will get ENOTSUP. If we
	 * are not privileged over the network namespace we will get EPERM.
	 */
	ret = lxc_netdev_delete_by_name("lo");
	if (ret == -ENOTSUP)
		bret = true;

do_full_cleanup:
	ret = setresuid(ruid, euid, suid);
	if (ret < 0) {
		CMD_SYSERROR("Failed to restore privilege by setting effective user id to %d, real user id to %d, and saved user ID to %d\n",
			     ruid, euid, suid);
		bret = false;
	}

	ret = setns(ofd, CLONE_NEWNET);
	if (ret < 0) {
		CMD_SYSERROR("Failed to setns() to original network namespace of PID %d\n",
			     ofd);
		bret = false;
	}

do_partial_cleanup:
	close(ofd);
	return bret;
}

static inline int validate_args(const struct user_nic_args *args, int argc)
{
	int request = -EINVAL;

	if (!strcmp(args->cmd, "create"))
		request = LXC_USERNIC_CREATE;
	else if (!strcmp(args->cmd, "delete"))
		request = LXC_USERNIC_DELETE;

	return request;
}

int main(int argc, char *argv[])
{
	__do_free char *me = NULL, *newname = NULL, *nicname = NULL;
	int fd, n, pid, request, ret;
	struct user_nic_args args;
	int container_veth_ifidx = -1, host_veth_ifidx = -1, netns_fd = -1;
	char *cnic = NULL;
	struct alloted_s *alloted = NULL;

	if (argc < 7 || argc > 8)
		usage(true);

	memset(&args, 0, sizeof(struct user_nic_args));

	args.cmd = argv[1];
	args.lxc_path = argv[2];
	args.lxc_name = argv[3];
	args.pid = argv[4];
	args.type = argv[5];
	args.link = argv[6];
	if (argc == 8)
		args.veth_name = argv[7];

	request = validate_args(&args, argc);
	if (request < 0)
		usage(true);

	/* Set a sane env, because we are setuid-root. */
	ret = clearenv();
	if (ret) {
		usernic_error("%s", "Failed to clear environment\n");
		_exit(EXIT_FAILURE);
	}

	ret = setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
	if (ret < 0) {
		usernic_error("%s", "Failed to set PATH, exiting\n");
		_exit(EXIT_FAILURE);
	}

	me = get_username();
	if (!me) {
		usernic_error("%s", "Failed to get username\n");
		_exit(EXIT_FAILURE);
	}

	if (request == LXC_USERNIC_CREATE) {
		ret = lxc_safe_int(args.pid, &pid);
		if (ret < 0) {
			usernic_error("Could not read pid: %s\n", args.pid);
			_exit(EXIT_FAILURE);
		}
	} else if (request == LXC_USERNIC_DELETE) {
		char opath[LXC_PROC_PID_FD_LEN];

		/* Open the path with O_PATH which will not trigger an actual
		 * open(). Don't report an errno to the caller to not leak
		 * information whether the path exists or not.
		 * When stracing setuid is stripped so this is not a concern
		 * either.
		 */
		netns_fd = open(args.pid, O_PATH | O_CLOEXEC);
		if (netns_fd < 0) {
			usernic_error("Failed to open \"%s\"\n", args.pid);
			_exit(EXIT_FAILURE);
		}

		if (!fhas_fs_type(netns_fd, NSFS_MAGIC)) {
			usernic_error("Path \"%s\" does not refer to a network namespace path\n", args.pid);
			close(netns_fd);
			_exit(EXIT_FAILURE);
		}

		ret = snprintf(opath, sizeof(opath), "/proc/self/fd/%d", netns_fd);
		if (ret < 0 || (size_t)ret >= sizeof(opath)) {
			close(netns_fd);
			_exit(EXIT_FAILURE);
		}

		/* Now get an fd that we can use in setns() calls. */
		ret = open(opath, O_RDONLY | O_CLOEXEC);
		if (ret < 0) {
			CMD_SYSERROR("Failed to open \"%s\"\n", args.pid);
			close(netns_fd);
			_exit(EXIT_FAILURE);
		}

		close(netns_fd);
		netns_fd = ret;
	}

	if (!create_db_dir(LXC_USERNIC_DB)) {
		usernic_error("%s", "Failed to create directory for db file\n");

		if (netns_fd >= 0)
			close(netns_fd);

		_exit(EXIT_FAILURE);
	}

	fd = open_and_lock(LXC_USERNIC_DB);
	if (fd < 0) {
		usernic_error("Failed to lock %s\n", LXC_USERNIC_DB);

		if (netns_fd >= 0)
			close(netns_fd);

		_exit(EXIT_FAILURE);
	}

	if (request == LXC_USERNIC_CREATE) {
		if (!may_access_netns(pid)) {
			usernic_error("User %s may not modify netns for pid %d\n", me, pid);
			_exit(EXIT_FAILURE);
		}
	} else if (request == LXC_USERNIC_DELETE) {
		bool has_priv;

		has_priv = is_privileged_over_netns(netns_fd);
		close(netns_fd);
		if (!has_priv) {
			usernic_error("%s", "Process is not privileged over network namespace\n");
			_exit(EXIT_FAILURE);
		}
	}

	n = get_alloted(me, args.type, args.link, &alloted);

	if (request == LXC_USERNIC_DELETE) {
		struct alloted_s *it;
		bool found_nicname = false;

		if (!is_ovs_bridge(args.link)) {
			usernic_error("%s", "Deletion of non ovs type network devices not implemented\n");
			close(fd);
			free_alloted(&alloted);
			_exit(EXIT_FAILURE);
		}

		/* Check whether the network device we are supposed to delete
		 * exists in the db. If it doesn't we will not delete it as we
		 * need to assume the network device is not under our control.
		 * As a side effect we also clear any invalid entries from the
		 * database.
		 */
		for (it = alloted; it; it = it->next)
			cull_entries(fd, it->name, args.type, args.link,
				     args.veth_name, &found_nicname);
		close(fd);
		free_alloted(&alloted);

		if (!found_nicname) {
			usernic_error("Caller is not allowed to delete network device \"%s\"\n", args.veth_name);
			_exit(EXIT_FAILURE);
		}

		ret = lxc_ovs_delete_port(args.link, args.veth_name);
		if (ret < 0) {
			usernic_error("Failed to remove port \"%s\" from openvswitch bridge \"%s\"", args.veth_name, args.link);
			_exit(EXIT_FAILURE);
		}

		_exit(EXIT_SUCCESS);
	}

	if (n > 0)
		nicname = get_nic_if_avail(fd, alloted, pid, args.type,
					   args.link, n, &cnic);

	close(fd);
	free_alloted(&alloted);

	if (!nicname) {
		usernic_error("%s", "Quota reached\n");
		_exit(EXIT_FAILURE);
	}

	/* Now rename the link. */
	newname = lxc_secure_rename_in_ns(pid, cnic, args.veth_name,
					  &container_veth_ifidx);
	if (!newname) {
		usernic_error("%s", "Failed to rename the link\n");

		ret = lxc_netdev_delete_by_name(cnic);
		if (ret < 0)
			usernic_error("Failed to delete \"%s\"\n", cnic);

		_exit(EXIT_FAILURE);
	}

	host_veth_ifidx = if_nametoindex(nicname);
	if (!host_veth_ifidx) {
		CMD_SYSERROR("Failed to get netdev index\n");
		_exit(EXIT_FAILURE);
	}

	/* Write names of veth pairs and their ifindices to stout:
	 * (e.g. eth0:731:veth9MT2L4:730)
	 */
	fprintf(stdout, "%s:%d:%s:%d\n", newname, container_veth_ifidx, nicname,
		host_veth_ifidx);

	fflush(stdout);
	_exit(EXIT_SUCCESS);
}
