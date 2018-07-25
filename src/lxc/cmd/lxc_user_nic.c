/*
 *
 * Copyright © 2013 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2013 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"
#include "namespace.h"
#include "network.h"
#include "parse.h"
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

static void usage(char *me, bool fail)
{
	fprintf(stderr, "Usage: %s create {lxcpath} {name} {pid} {type} "
			"{bridge} {nicname}\n", me);
	fprintf(stderr, "Usage: %s delete {lxcpath} {name} "
			"{/proc/<pid>/ns/net} {type} {bridge} {nicname}\n", me);
	fprintf(stderr, "{nicname} is the name to use inside the container\n");

	if (fail)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}

static int open_and_lock(char *path)
{
	int fd, ret;
	struct flock lk;

	fd = open(path, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		usernic_error("Failed to open \"%s\": %s\n", path,
			      strerror(errno));
		return -1;
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;

	ret = fcntl(fd, F_SETLKW, &lk);
	if (ret < 0) {
		usernic_error("Failed to lock \"%s\": %s\n", path,
			      strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static char *get_username(void)
{
	struct passwd pwent;
	struct passwd *pwentp = NULL;
	char *buf;
	char *username;
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

		usernic_error("Failed to get username: %s(%u)\n", strerror(errno), getuid());
		free(buf);
		return NULL;
	}

	username = strdup(pwent.pw_name);
	free(buf);

	return username;
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
	int ngroups;
	gid_t *group_ids;
	int ret, i;
	char **groupnames;
	struct group grent;
	struct group *grentp = NULL;
	char *buf;
	size_t bufsize;

	ngroups = getgroups(0, NULL);
	if (ngroups < 0) {
		usernic_error("Failed to get number of groups the user "
			      "belongs to: %s\n", strerror(errno));
		return NULL;
	}
	if (ngroups == 0)
		return NULL;

	group_ids = malloc(sizeof(gid_t) * ngroups);
	if (!group_ids) {
		usernic_error("Failed to allocate memory while getting groups "
			      "the user belongs to: %s\n",
			      strerror(errno));
		return NULL;
	}

	ret = getgroups(ngroups, group_ids);
	if (ret < 0) {
		free(group_ids);
		usernic_error("Failed to get process groups: %s\n",
			      strerror(errno));
		return NULL;
	}

	groupnames = malloc(sizeof(char *) * (ngroups + 1));
	if (!groupnames) {
		free(group_ids);
		usernic_error("Failed to allocate memory while getting group "
			      "names: %s\n",
			      strerror(errno));
		return NULL;
	}

	memset(groupnames, 0, sizeof(char *) * (ngroups + 1));

	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 1024;

	buf = malloc(bufsize);
	if (!buf) {
		free(group_ids);
		free_groupnames(groupnames);
		usernic_error("Failed to allocate memory while getting group "
			      "names: %s\n",
			      strerror(errno));
		return NULL;
	}

	for (i = 0; i < ngroups; i++) {
		ret = getgrgid_r(group_ids[i], &grent, buf, bufsize, &grentp);
		if (!grentp) {
			if (ret == 0)
				usernic_error("%s", "Could not find matched group record\n");

			usernic_error("Failed to get group name: %s(%u)\n",
			      strerror(errno), group_ids[i]);
			free(buf);
			free(group_ids);
			free_groupnames(groupnames);
			return NULL;
		}

		groupnames[i] = strdup(grent.gr_name);
		if (!groupnames[i]) {
			usernic_error("Failed to copy group name \"%s\"",
				      grent.gr_name);
			free(buf);
			free(group_ids);
			free_groupnames(groupnames);
			return NULL;
		}
	}

	free(buf);
	free(group_ids);

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
		usernic_error("Failed to allocate memory: %s\n",
			      strerror(errno));
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
	int n, ret;
	char name[100], type[100], br[100];
	char **groups;
	FILE *fin;

	int count = 0;
	size_t len = 0;
	char *line = NULL;

	fin = fopen(LXC_USERNIC_CONF, "r");
	if (!fin) {
		usernic_error("Failed to open \"%s\": %s\n", LXC_USERNIC_CONF,
			      strerror(errno));
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
	fclose(fin);
	free(line);

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

static int instantiate_veth(char *veth1, char *veth2)
{
	int ret;

	ret = lxc_veth_create(veth1, veth2);
	if (ret < 0) {
		usernic_error("Failed to create %s-%s : %s.\n", veth1, veth2,
			      strerror(-ret));
		return -1;
	}

	/* Changing the high byte of the mac address to 0xfe, the bridge
	 * interface will always keep the host's mac address and not take the
	 * mac address of a container. */
	ret = setup_private_host_hw_addr(veth1);
	if (ret < 0)
		usernic_error("Failed to change mac address of host interface "
			      "%s : %s\n", veth1, strerror(-ret));

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
	char veth1buf[IFNAMSIZ], veth2buf[IFNAMSIZ];
	int mtu, ret;

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
	/* create the nics */
	ret = instantiate_veth(veth1buf, veth2buf);
	if (ret < 0) {
		usernic_error("%s", "Error creating veth tunnel\n");
		return -1;
	}

	if (strcmp(br, "none")) {
		/* copy the bridge's mtu to both ends */
		mtu = get_mtu(br);
		if (mtu > 0) {
			ret = lxc_netdev_set_mtu(veth1buf, mtu);
			if (ret < 0) {
				usernic_error("Failed to set mtu to %d on %s\n",
					      mtu, veth1buf);
				goto out_del;
			}

			ret = lxc_netdev_set_mtu(veth2buf, mtu);
			if (ret < 0) {
				usernic_error("Failed to set mtu to %d on %s\n",
					      mtu, veth2buf);
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

	/* pass veth2 to target netns */
	ret = lxc_netdev_move_by_name(veth2buf, pid, NULL);
	if (ret < 0) {
		usernic_error("Error moving %s to network namespace of %d\n",
			      veth2buf, pid);
		goto out_del;
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
	int i, ret;
	char *buf, *buf_end, *buf_start;
	struct stat sb;
	int n = 0;
	bool found, keep;
	struct entry_line *entry_lines = NULL;

	ret = fstat(fd, &sb);
	if (ret < 0) {
		usernic_error("Failed to fstat: %s\n", strerror(errno));
		return false;
	}

	if (!sb.st_size)
		return false;

	buf = lxc_strmmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		usernic_error("Failed to establish shared memory mapping: %s\n",
			      strerror(errno));
		return false;
	}

	buf_start = buf;
	buf_end = buf + sb.st_size;
	while ((buf_start = find_line(buf_start, buf_end, name, net_type,
				      net_link, net_dev, &(bool){true}, &found,
				      &keep))) {
		struct entry_line *newe;

		newe = realloc(entry_lines, sizeof(*entry_lines) * (n + 1));
		if (!newe) {
			free(entry_lines);
			lxc_strmunmap(buf, sb.st_size);
			return false;
		}

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
	for (i = 0; i < n; i++) {
		if (!entry_lines[i].keep)
			continue;

		memcpy(buf_start, entry_lines[i].start, entry_lines[i].len);
		buf_start += entry_lines[i].len;
		*buf_start = '\n';
		buf_start++;
	}
	free(entry_lines);

	ret = ftruncate(fd, buf_start - buf);
	lxc_strmunmap(buf, sb.st_size);
	if (ret < 0)
		usernic_error("Failed to set new file size: %s\n",
			      strerror(errno));

	return true;
}

static int count_entries(char *buf, off_t len, char *name, char *net_type, char *net_link)
{
	int count = 0;
	bool owner = false;;
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
	int ret;
	size_t slen;
	char *newline, *owner;
	char nicname[IFNAMSIZ];
	struct stat sb;
	struct alloted_s *n;
	int count = 0;
	char *buf = NULL;

	for (n = names; n != NULL; n = n->next)
		cull_entries(fd, n->name, intype, br, NULL, NULL);

	if (allowed == 0)
		return NULL;

	owner = names->name;

	ret = fstat(fd, &sb);
	if (ret < 0) {
		usernic_error("Failed to fstat: %s\n", strerror(errno));
		return NULL;
	}

	if (sb.st_size > 0) {
		buf = lxc_strmmap(NULL, sb.st_size, PROT_READ | PROT_WRITE,
				  MAP_SHARED, fd, 0);
		if (buf == MAP_FAILED) {
			usernic_error("Failed to establish shared memory "
				      "mapping: %s\n", strerror(errno));
			return NULL;
		}

		owner = NULL;
		for (n = names; n != NULL; n = n->next) {
			count = count_entries(buf, sb.st_size, n->name, intype, br);
			if (count >= n->allowed)
				continue;

			owner = n->name;
			break;
		}

		lxc_strmunmap(buf, sb.st_size);
	}

	if (owner == NULL)
		return NULL;

	ret = snprintf(nicname, sizeof(nicname), "vethXXXXXX");
	if (ret < 0 || (size_t)ret >= sizeof(nicname))
		return NULL;

	if (!lxc_mkifname(nicname))
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
		free(newline);
		usernic_error("Failed allocate memory: %s\n", strerror(errno));
		return NULL;
	}

	ret = snprintf(newline, slen + 1, "%s %s %s %s\n", owner, intype, br, nicname);
	if (ret < 0 || (size_t)ret >= (slen + 1)) {
		if (lxc_netdev_delete_by_name(nicname) != 0)
			usernic_error("Error unlinking %s\n", nicname);
		free(newline);
		return NULL;
	}

	/* Note that the file needs to be truncated to the size **without** the
	 * \0 byte! Files are not \0-terminated!
	 */
	ret = ftruncate(fd, sb.st_size + slen);
	if (ret < 0)
		usernic_error("Failed to truncate file: %s\n", strerror(errno));

	buf = lxc_strmmap(NULL, sb.st_size + slen, PROT_READ | PROT_WRITE,
			  MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		usernic_error("Failed to establish shared memory mapping: %s\n",
			      strerror(errno));
		if (lxc_netdev_delete_by_name(nicname) != 0)
			usernic_error("Error unlinking %s\n", nicname);
		free(newline);
		return NULL;
	}

	/* Note that the memory needs to be moved in the buffer **without** the
	 * \0 byte! Files are not \0-terminated!
	 */
	memmove(buf + sb.st_size, newline, slen);
	free(newline);
	lxc_strmunmap(buf, sb.st_size + slen);

	return strdup(nicname);
}

static bool create_db_dir(char *fnam)
{
	int ret;
	char *p;
	size_t len;

	len = strlen(fnam);
	p = alloca(len + 1);
	(void)strlcpy(p, fnam, len + 1);
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
		usernic_error("Failed to create %s: %s\n", fnam,
			      strerror(errno));
		*p = '/';
		return false;
	}
	*(p++) = '/';

	goto again;
}

static char *lxc_secure_rename_in_ns(int pid, char *oldname, char *newname,
				     int *container_veth_ifidx)
{
	int ret;
	pid_t pid_self;
	uid_t ruid, suid, euid;
	char ifname[IFNAMSIZ];
	char *string_ret = NULL, *name = NULL;
	int fd = -1, ifindex = -1, ofd = -1;

	pid_self = lxc_raw_getpid();
	ofd = lxc_preserve_ns(pid_self, "net");
	if (ofd < 0) {
		usernic_error("Failed opening network namespace path for %d", pid_self);
		return NULL;
	}

	fd = lxc_preserve_ns(pid, "net");
	if (fd < 0) {
		usernic_error("Failed opening network namespace path for %d", pid);
		goto do_partial_cleanup;
	}

	ret = getresuid(&ruid, &euid, &suid);
	if (ret < 0) {
		usernic_error("Failed to retrieve real, effective, and saved "
			      "user IDs: %s\n",
			      strerror(errno));
		goto do_partial_cleanup;
	}

	ret = setns(fd, CLONE_NEWNET);
	close(fd);
	fd = -1;
	if (ret < 0) {
		usernic_error("Failed to setns() to the network namespace of "
			      "the container with PID %d: %s\n",
			      pid, strerror(errno));
		goto do_partial_cleanup;
	}

	ret = setresuid(ruid, ruid, 0);
	if (ret < 0) {
		usernic_error("Failed to drop privilege by setting effective "
			      "user id and real user id to %d, and saved user "
			      "ID to 0: %s\n",
			      ruid, strerror(errno));
		/* It's ok to jump to do_full_cleanup here since setresuid()
		 * will succeed when trying to set real, effective, and saved to
		 * values they currently have.
		 */
		goto do_full_cleanup;
	}

	/* Check if old interface exists. */
	ifindex = if_nametoindex(oldname);
	if (!ifindex) {
		usernic_error("Failed to get netdev index: %s\n", strerror(errno));
		goto do_full_cleanup;
	}

	/* When the IFLA_IFNAME attribute is passed something like "<prefix>%d"
	 * netlink will replace the format specifier with an appropriate index.
	 * So we pass "eth%d".
	 */
	if (newname)
		name = newname;
	else
		name = "eth%d";

	ret = lxc_netdev_rename_by_name(oldname, name);
	name = NULL;
	if (ret < 0) {
		usernic_error("Error %d renaming netdev %s to %s in container\n",
			      ret, oldname, newname ? newname : "eth%d");
		goto do_full_cleanup;
	}

	/* Retrieve new name for interface. */
	if (!if_indextoname(ifindex, ifname)) {
		usernic_error("Failed to get new netdev name: %s\n", strerror(errno));
		goto do_full_cleanup;
	}

	/* Allocation failure for strdup() is checked below. */
	name = strdup(ifname);
	string_ret = name;
	*container_veth_ifidx = ifindex;

do_full_cleanup:
	ret = setresuid(ruid, euid, suid);
	if (ret < 0) {
		usernic_error("Failed to restore privilege by setting "
			      "effective user id to %d, real user id to %d, "
			      "and saved user ID to %d: %s\n", ruid, euid, suid,
			      strerror(errno));

		string_ret = NULL;
	}

	ret = setns(ofd, CLONE_NEWNET);
	if (ret < 0) {
		usernic_error("Failed to setns() to original network namespace "
			      "of PID %d: %s\n", ofd, strerror(errno));

		string_ret = NULL;
	}

do_partial_cleanup:
	if (fd >= 0)
		close(fd);

	if (!string_ret && name)
		free(name);

	close(ofd);

	return string_ret;
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
		usernic_error("Failed to retrieve real, effective, and saved "
			      "user IDs: %s\n",
			      strerror(errno));
		return false;
	}

	ret = setresuid(ruid, ruid, euid);
	if (ret < 0) {
		usernic_error("Failed to drop privilege by setting effective "
			      "user id and real user id to %d, and saved user "
			      "ID to %d: %s\n",
			      ruid, euid, strerror(errno));
		return false;
	}

	ret = snprintf(s, 200, "/proc/%d/ns/net", pid);
	if (ret < 0 || ret >= 200)
		return false;

	ret = access(s, R_OK);
	may_access = true;
	if (ret < 0)  {
		may_access = false;
		usernic_error("Uid %d may not access %s: %s\n", (int)ruid, s, strerror(errno));
	}

	ret = setresuid(ruid, euid, suid);
	if (ret < 0) {
		usernic_error("Failed to restore user id to %d, real user id "
			      "to %d, and saved user ID to %d: %s\n",
			      ruid, euid, suid, strerror(errno));
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

#define LXC_USERNIC_CREATE 0
#define LXC_USERNIC_DELETE 1

static bool is_privileged_over_netns(int netns_fd)
{
	int ret;
	pid_t pid_self;
	uid_t euid, ruid, suid;
	bool bret = false;
	int ofd = -1;

	pid_self = lxc_raw_getpid();
	ofd = lxc_preserve_ns(pid_self, "net");
	if (ofd < 0) {
		usernic_error("Failed opening network namespace path for %d", pid_self);
		return false;
	}

	ret = getresuid(&ruid, &euid, &suid);
	if (ret < 0) {
		usernic_error("Failed to retrieve real, effective, and saved "
			      "user IDs: %s\n",
			      strerror(errno));
		goto do_partial_cleanup;
	}

	ret = setns(netns_fd, CLONE_NEWNET);
	if (ret < 0) {
		usernic_error("Failed to setns() to network namespace %s\n",
			      strerror(errno));
		goto do_partial_cleanup;
	}

	ret = setresuid(ruid, ruid, 0);
	if (ret < 0) {
		usernic_error("Failed to drop privilege by setting effective "
			      "user id and real user id to %d, and saved user "
			      "ID to 0: %s\n",
			      ruid, strerror(errno));
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
		usernic_error("Failed to restore privilege by setting "
			      "effective user id to %d, real user id to %d, "
			      "and saved user ID to %d: %s\n", ruid, euid, suid,
			      strerror(errno));

		bret = false;
	}

	ret = setns(ofd, CLONE_NEWNET);
	if (ret < 0) {
		usernic_error("Failed to setns() to original network namespace "
			      "of PID %d: %s\n", ofd, strerror(errno));

		bret = false;
	}

do_partial_cleanup:

	close(ofd);
	return bret;
}

int main(int argc, char *argv[])
{
	int fd, n, pid, request, ret;
	char *me, *newname;
	struct user_nic_args args;
	int container_veth_ifidx = -1, host_veth_ifidx = -1, netns_fd = -1;
	char *cnic = NULL, *nicname = NULL;
	struct alloted_s *alloted = NULL;

	if (argc < 7 || argc > 8) {
		usage(argv[0], true);
		exit(EXIT_FAILURE);
	}

	memset(&args, 0, sizeof(struct user_nic_args));
	args.cmd = argv[1];
	args.lxc_path = argv[2];
	args.lxc_name = argv[3];
	args.pid = argv[4];
	args.type = argv[5];
	args.link = argv[6];
	if (argc >= 8)
		args.veth_name = argv[7];

	if (!strcmp(args.cmd, "create")) {
		request = LXC_USERNIC_CREATE;
	} else if (!strcmp(args.cmd, "delete")) {
		request = LXC_USERNIC_DELETE;
	} else {
		usage(argv[0], true);
		exit(EXIT_FAILURE);
	}

	/* Set a sane env, because we are setuid-root. */
	ret = clearenv();
	if (ret) {
		usernic_error("%s", "Failed to clear environment\n");
		exit(EXIT_FAILURE);
	}

	ret = setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
	if (ret < 0) {
		usernic_error("%s", "Failed to set PATH, exiting\n");
		exit(EXIT_FAILURE);
	}

	me = get_username();
	if (!me) {
		usernic_error("%s", "Failed to get username\n");
		exit(EXIT_FAILURE);
	}

	if (request == LXC_USERNIC_CREATE) {
		ret = lxc_safe_int(args.pid, &pid);
		if (ret < 0) {
			usernic_error("Could not read pid: %s\n", args.pid);
			exit(EXIT_FAILURE);
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
			exit(EXIT_FAILURE);
		}

		if (!fhas_fs_type(netns_fd, NSFS_MAGIC)) {
			usernic_error("Path \"%s\" does not refer to a network namespace path\n", args.pid);
			close(netns_fd);
			exit(EXIT_FAILURE);
		}

		ret = snprintf(opath, sizeof(opath), "/proc/self/fd/%d", netns_fd);
		if (ret < 0 || (size_t)ret >= sizeof(opath)) {
			close(netns_fd);
			exit(EXIT_FAILURE);
		}

		/* Now get an fd that we can use in setns() calls. */
		ret = open(opath, O_RDONLY | O_CLOEXEC);
		if (ret < 0) {
			usernic_error("Failed to open \"%s\": %s\n", args.pid, strerror(errno));
			close(netns_fd);
			exit(EXIT_FAILURE);
		}
		close(netns_fd);
		netns_fd = ret;
	}

	if (!create_db_dir(LXC_USERNIC_DB)) {
		usernic_error("%s", "Failed to create directory for db file\n");
		if (netns_fd >= 0)
			close(netns_fd);
		exit(EXIT_FAILURE);
	}

	fd = open_and_lock(LXC_USERNIC_DB);
	if (fd < 0) {
		usernic_error("Failed to lock %s\n", LXC_USERNIC_DB);
		if (netns_fd >= 0)
			close(netns_fd);
		exit(EXIT_FAILURE);
	}

	if (request == LXC_USERNIC_CREATE) {
		if (!may_access_netns(pid)) {
			usernic_error("User %s may not modify netns for pid %d\n", me, pid);
			exit(EXIT_FAILURE);
		}
	} else if (request == LXC_USERNIC_DELETE) {
		bool has_priv;
		has_priv = is_privileged_over_netns(netns_fd);
		close(netns_fd);
		if (!has_priv) {
			usernic_error("%s", "Process is not privileged over "
					    "network namespace\n");
			exit(EXIT_FAILURE);
		}
	}

	n = get_alloted(me, args.type, args.link, &alloted);
	free(me);

	if (request == LXC_USERNIC_DELETE) {
		int ret;
		struct alloted_s *it;
		bool found_nicname = false;

		if (!is_ovs_bridge(args.link)) {
			usernic_error("%s", "Deletion of non ovs type network "
					    "devices not implemented\n");
			close(fd);
			free_alloted(&alloted);
			exit(EXIT_FAILURE);
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
			usernic_error("Caller is not allowed to delete network "
				      "device \"%s\"\n", args.veth_name);
			exit(EXIT_FAILURE);
		}

		ret = lxc_ovs_delete_port(args.link, args.veth_name);
		if (ret < 0) {
			usernic_error("Failed to remove port \"%s\" from "
				      "openvswitch bridge \"%s\"",
				      args.veth_name, args.link);
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}
	if (n > 0)
		nicname = get_nic_if_avail(fd, alloted, pid, args.type,
					   args.link, n, &cnic);

	close(fd);
	free_alloted(&alloted);
	if (!nicname) {
		usernic_error("%s", "Quota reached\n");
		exit(EXIT_FAILURE);
	}

	/* Now rename the link. */
	newname = lxc_secure_rename_in_ns(pid, cnic, args.veth_name,
					  &container_veth_ifidx);
	if (!newname) {
		usernic_error("%s", "Failed to rename the link\n");
		ret = lxc_netdev_delete_by_name(cnic);
		if (ret < 0)
			usernic_error("Failed to delete \"%s\"\n", cnic);
		free(nicname);
		exit(EXIT_FAILURE);
	}

	host_veth_ifidx = if_nametoindex(nicname);
	if (!host_veth_ifidx) {
		free(newname);
		free(nicname);
		usernic_error("Failed to get netdev index: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Write names of veth pairs and their ifindeces to stout:
	 * (e.g. eth0:731:veth9MT2L4:730)
	 */
	fprintf(stdout, "%s:%d:%s:%d\n", newname, container_veth_ifidx, nicname,
		host_veth_ifidx);
	free(newname);
	free(nicname);
	exit(EXIT_SUCCESS);
}
