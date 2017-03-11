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

#define _GNU_SOURCE             /* See feature_test_macros(7) */
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
#include "network.h"
#include "utils.h"

#define usernic_debug_stream(stream, format, ...)                              \
	do {                                                                   \
		fprintf(stream, "%s: %d: %s: " format, __FILE__, __LINE__,     \
			__func__, __VA_ARGS__);                                \
	} while (false)

#define usernic_error(format, ...) usernic_debug_stream(stderr, format, __VA_ARGS__)

static void usage(char *me, bool fail)
{
	fprintf(stderr, "Usage: %s lxcpath name pid type bridge nicname\n", me);
	fprintf(stderr, " nicname is the name to use inside the container\n");
	exit(fail ? 1 : 0);
}

static char *lxcpath, *lxcname;

static int open_and_lock(char *path)
{
	int fd;
	struct flock lk;

	fd = open(path, O_RDWR|O_CREAT, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		usernic_error("Failed to open %s: %s.\n", path, strerror(errno));
		return -1;
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;
	if (fcntl(fd, F_SETLKW, &lk) < 0) {
		usernic_error("Failed to lock %s: %s.\n", path, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}


static char *get_username(void)
{
	struct passwd *pwd;

	pwd = getpwuid(getuid());
	if (!pwd) {
		usernic_error("Failed to call get username: %s.\n", strerror(errno));
		return NULL;
	}

	return pwd->pw_name;
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
	struct group *gr;

	ngroups = getgroups(0, NULL);
	if (ngroups < 0) {
		usernic_error(
		    "Failed to get number of groups the user belongs to: %s.\n",
		    strerror(errno));
		return NULL;
	}
	if (ngroups == 0)
		return NULL;

	group_ids = malloc(sizeof(gid_t) * ngroups);
	if (!group_ids) {
		usernic_error("Failed to allocate memory while getting groups "
			      "the user belongs to: %s.\n",
			      strerror(errno));
		return NULL;
	}

	ret = getgroups(ngroups, group_ids);
	if (ret < 0) {
		free(group_ids);
		usernic_error("Failed to get process groups: %s.\n",
			      strerror(errno));
		return NULL;
	}

	groupnames = malloc(sizeof(char *) * (ngroups + 1));
	if (!groupnames) {
		free(group_ids);
		usernic_error("Failed to allocate memory while getting group "
			      "names: %s.\n",
			      strerror(errno));
		return NULL;
	}

	memset(groupnames, 0, sizeof(char *) * (ngroups + 1));

	for (i = 0; i < ngroups; i++) {
		gr = getgrgid(group_ids[i]);
		if (!gr) {
			usernic_error("Failed to get group name: %s.\n",
				      strerror(errno));
			free(group_ids);
			free_groupnames(groupnames);
			return NULL;
		}

		groupnames[i] = strdup(gr->gr_name);
		if (!groupnames[i]) {
			usernic_error("Failed to copy group name \"%s\".",
				      gr->gr_name);
			free(group_ids);
			free_groupnames(groupnames);
			return NULL;
		}
	}

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

static struct alloted_s *append_alloted(struct alloted_s **head, char *name, int n)
{
	struct alloted_s *cur, *al;

	if (!head || !name) {
		// sanity check. parameters should not be null
		usernic_error("%s\n", "Unexpected NULL argument.");
		return NULL;
	}

	al = malloc(sizeof(struct alloted_s));
	if (!al) {
		usernic_error("Failed to allocate memory: %s.\n", strerror(errno));
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
static int get_alloted(char *me, char *intype, char *link, struct alloted_s **alloted)
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
		usernic_error("Failed to open \"%s\": %s.\n", LXC_USERNIC_CONF, strerror(errno));
		return -1;
	}

	groups = get_groupnames();
	while ((getline(&line, &len, fin)) != -1) {
		ret = sscanf(line, "%99[^ \t] %99[^ \t] %99[^ \t] %d", name, type, br, &n);
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

static char *find_line(char *p, char *e, char *u, char *t, char *l)
{
	char *p1, *p2, *ret;

	while ((p < e) && (p1 = get_eol(p, e)) < e) {
		ret = p;
		if (*p == '#')
			goto next;

		while ((p < e) && isblank(*p))
			p++;

		p2 = get_eow(p, e);
		if (!p2 || ((size_t)(p2 - p)) != strlen(u) || strncmp(p, u, strlen(u)))
			goto next;

		p = p2 + 1;
		while ((p < e) && isblank(*p))
			p++;

		p2 = get_eow(p, e);
		if (!p2 || ((size_t)(p2 - p)) != strlen(t) || strncmp(p, t, strlen(t)))
			goto next;

		p = p2 + 1;
		while ((p < e) && isblank(*p))
			p++;

		p2 = get_eow(p, e);
		if (!p2 || ((size_t)(p2 - p)) != strlen(l) || strncmp(p, l, strlen(l)))
			goto next;

		return ret;
next:
		p = p1 + 1;
	}

	return NULL;
}

static bool nic_exists(char *nic)
{
	char path[MAXPATHLEN];
	int ret;
	struct stat sb;

	if (!strcmp(nic, "none"))
		return true;

	ret = snprintf(path, MAXPATHLEN, "/sys/class/net/%s", nic);
	if (ret < 0 || ret >= MAXPATHLEN)
		return false;

	ret = stat(path, &sb);
	if (ret < 0)
		return false;

	return true;
}

static int instantiate_veth(char *n1, char **n2)
{
	int err;

	err = snprintf(*n2, IFNAMSIZ, "%sp", n1);
	if (err < 0 || err >= IFNAMSIZ) {
		usernic_error("%s\n", "Could not create nic name.");
		return -1;
	}

	err = lxc_veth_create(n1, *n2);
	if (err) {
		usernic_error("Failed to create %s-%s : %s.\n", n1, *n2, strerror(-err));
		return -1;
	}

	/* Changing the high byte of the mac address to 0xfe, the bridge
	 * interface will always keep the host's mac address and not take the
	 * mac address of a container. */
	err = setup_private_host_hw_addr(n1);
	if (err)
		usernic_error("Failed to change mac address of host interface "
			      "%s : %s.\n",
			      n1, strerror(-err));

	return netdev_set_flag(n1, IFF_UP);
}

static int get_mtu(char *name)
{
	int idx;

	idx = if_nametoindex(name);
	return netdev_get_mtu(idx);
}

static bool create_nic(char *nic, char *br, int pid, char **cnic)
{
	char *veth1buf, *veth2buf;
	int mtu, ret;

	veth1buf = alloca(IFNAMSIZ);
	veth2buf = alloca(IFNAMSIZ);
	if (!veth1buf || !veth2buf) {
		usernic_error("Failed allocate memory: %s.\n", strerror(errno));
		return false;
	}

	ret = snprintf(veth1buf, IFNAMSIZ, "%s", nic);
	if (ret < 0 || ret >= IFNAMSIZ) {
		usernic_error("%s", "Could not create nic name.\n");
		return false;
	}

	/* create the nics */
	if (instantiate_veth(veth1buf, &veth2buf) < 0) {
		usernic_error("%s", "Error creating veth tunnel.\n");
		return false;
	}

	if (strcmp(br, "none")) {
		/* copy the bridge's mtu to both ends */
		mtu = get_mtu(br);
		if (mtu > 0) {
			ret = lxc_netdev_set_mtu(veth1buf, mtu);
			if (ret < 0) {
				usernic_error("Failed to set mtu to %d on %s.\n", mtu, veth1buf);
				goto out_del;
			}

			ret = lxc_netdev_set_mtu(veth2buf, mtu);
			if (ret < 0) {
				usernic_error("Failed to set mtu to %d on %s.\n", mtu, veth2buf);
				goto out_del;
			}
		}

		/* attach veth1 to bridge */
		ret = lxc_bridge_attach(lxcpath, lxcname, br, veth1buf);
		if (ret < 0) {
			usernic_error("Error attaching %s to %s.\n", veth1buf, br);
			goto out_del;
		}
	}

	/* pass veth2 to target netns */
	ret = lxc_netdev_move_by_name(veth2buf, pid, NULL);
	if (ret < 0) {
		usernic_error("Error moving %s to network namespace of %d.\n", veth2buf, pid);
		goto out_del;
	}

	*cnic = strdup(veth2buf);
	if (!*cnic) {
		usernic_error("Failed to copy string \"%s\".\n", veth2buf);
		return false;
	}

	return true;

out_del:
	lxc_netdev_delete_by_name(veth1buf);
	return false;
}

/*
 * Get a new nic.
 * *dest will contain the name (vethXXXXXX) which is attached
 * on the host to the lxc bridge
 */
static bool get_new_nicname(char **dest, char *br, int pid, char **cnic)
{
	int ret;
	char template[IFNAMSIZ];

	ret = snprintf(template, sizeof(template), "vethXXXXXX");
	if (ret < 0 || (size_t)ret >= sizeof(template))
		return false;

	*dest = lxc_mkifname(template);
	if (!create_nic(*dest, br, pid, cnic))
		return false;

	return true;
}

static bool get_nic_from_line(char *p, char **nic)
{
	int ret;
	char user[100], type[100], br[100];

	ret = sscanf(p, "%99[^ \t\n] %99[^ \t\n] %99[^ \t\n] %99[^ \t\n]", user, type, br, *nic);
	if (ret != 4)
		return false;

	return true;
}

struct entry_line {
	char *start;
	int len;
	bool keep;
};

static bool cull_entries(int fd, char *me, char *t, char *br)
{
	int i, n = 0;
	off_t len;
	char *buf, *p, *e, *nic;
	struct stat sb;
	struct entry_line *entry_lines = NULL;

	nic = alloca(100);
	if (!nic)
		return false;

	if (fstat(fd, &sb) < 0) {
		usernic_error("Failed to fstat: %s.\n", strerror(errno));
		return false;
	}

	len = sb.st_size;
	if (len == 0)
		return true;

	buf = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		usernic_error("Failed to establish shared memory mapping: %s.\n", strerror(errno));
		return false;
	}

	p = buf;
	e = buf + len;
	while ((p = find_line(p, e, me, t, br))) {
		struct entry_line *newe;

		newe = realloc(entry_lines, sizeof(*entry_lines) * (n + 1));
		if (!newe) {
			free(entry_lines);
			return false;
		}

		entry_lines = newe;
		entry_lines[n].start = p;
		entry_lines[n].len = get_eol(p, e) - entry_lines[n].start;
		entry_lines[n].keep = true;
		n++;
		if (!get_nic_from_line(p, &nic))
			continue;

		if (nic && !nic_exists(nic))
			entry_lines[n - 1].keep = false;

		p += entry_lines[n - 1].len + 1;
		if (p >= e)
			break;
	}

	p = buf;
	for (i = 0; i < n; i++) {
		if (!entry_lines[i].keep)
			continue;

		memcpy(p, entry_lines[i].start, entry_lines[i].len);
		p += entry_lines[i].len;
		*p = '\n';
		p++;
	}
	free(entry_lines);

	munmap(buf, sb.st_size);
	if (ftruncate(fd, p - buf))
		usernic_error("Failed to set new file size: %s.\n", strerror(errno));

	return true;
}

static int count_entries(char *buf, off_t len, char *me, char *t, char *br)
{
	char *e;
	int count = 0;

	e = &buf[len];
	while ((buf = find_line(buf, e, me, t, br))) {
		count++;
		buf = get_eol(buf, e) + 1;
		if (buf >= e)
			break;
	}

	return count;
}

/*
 * The dbfile has lines of the format:
 * user type bridge nicname
 */
static bool get_nic_if_avail(int fd, struct alloted_s *names, int pid,
			     char *intype, char *br, int allowed,
			     char **nicname, char **cnic)
{
	int ret;
	off_t len, slen;
	char *newline, *owner;
	struct stat sb;
	struct alloted_s *n;
	int count = 0;
	char *buf = NULL;

	for (n = names; n != NULL; n = n->next)
		cull_entries(fd, n->name, intype, br);

	if (allowed == 0)
		return false;

	owner = names->name;

	if (fstat(fd, &sb) < 0) {
		usernic_error("Failed to fstat: %s.\n", strerror(errno));
		return false;
	}

	len = sb.st_size;
	if (len > 0) {
		buf = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if (buf == MAP_FAILED) {
			usernic_error("Failed to establish shared memory mapping: %s.\n", strerror(errno));
			return false;
		}

		owner = NULL;
		for (n = names; n != NULL; n = n->next) {
			count = count_entries(buf, len, n->name, intype, br);

			if (count >= n->allowed)
				continue;

			owner = n->name;
			break;
		}
	}

	if (owner == NULL)
		return false;

	if (!get_new_nicname(nicname, br, pid, cnic))
		return false;

	/* owner  ' ' intype ' ' br ' ' *nicname + '\n' + '\0' */
	slen = strlen(owner) + strlen(intype) + strlen(br) + strlen(*nicname) + 5;
	newline = alloca(slen);
	if (!newline) {
		usernic_error("Failed allocate memory: %s.\n", strerror(errno));
		return false;
	}

	ret = snprintf(newline, slen, "%s %s %s %s\n", owner, intype, br, *nicname);
	if (ret < 0 || ret >= slen) {
		if (lxc_netdev_delete_by_name(*nicname) != 0)
			usernic_error("Error unlinking %s.\n", *nicname);
		return false;
	}
	if (len)
		munmap(buf, len);

	if (ftruncate(fd, len + slen))
		usernic_error("Failed to set new file size: %s.\n", strerror(errno));

	buf = mmap(NULL, len + slen, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		usernic_error("Failed to establish shared memory mapping: %s.\n", strerror(errno));
		if (lxc_netdev_delete_by_name(*nicname) != 0)
			usernic_error("Error unlinking %s.\n", *nicname);
		return false;
	}

	strcpy(buf + len, newline);
	munmap(buf, len + slen);

	return true;
}

static bool create_db_dir(char *fnam)
{
	char *p;

	p = alloca(strlen(fnam) + 1);
	strcpy(p, fnam);
	fnam = p;
	p = p + 1;

again:
	while (*p && *p != '/')
		p++;
	if (!*p)
		return true;

	*p = '\0';
	if (mkdir(fnam, 0755) && errno != EEXIST) {
		usernic_error("Failed to create %s: %s.\n", fnam, strerror(errno));
		*p = '/';
		return false;
	}
	*(p++) = '/';

	goto again;
}

#define VETH_DEF_NAME "eth%d"
static int rename_in_ns(int pid, char *oldname, char **newnamep)
{
	uid_t ruid, suid, euid;
	int fret = -1;
	int fd = -1, ifindex = -1, ofd = -1, ret;
	bool grab_newname = false;

	ofd = lxc_preserve_ns(getpid(), "net");
	if (ofd < 0) {
		usernic_error("Failed opening network namespace path for '%d'.", getpid());
		return fret;
	}

	fd = lxc_preserve_ns(pid, "net");
	if (fd < 0) {
		usernic_error("Failed opening network namespace path for '%d'.", pid);
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
			      "the container with PID %d: %s.\n",
			      pid, strerror(errno));
		goto do_partial_cleanup;
	}

	ret = setresuid(ruid, ruid, 0);
	if (ret < 0) {
		usernic_error("Failed to drop privilege by setting effective "
			      "user id and real user id to %d, and saved user "
			      "ID to 0: %s.\n",
			      ruid, strerror(errno));
		// COMMENT(brauner): It's ok to jump to do_full_cleanup here
		// since setresuid() will succeed when trying to set real,
		// effective, and saved to values they currently have.
		goto do_full_cleanup;
	}

	if (!*newnamep) {
		grab_newname = true;
		*newnamep = VETH_DEF_NAME;

		ifindex = if_nametoindex(oldname);
		if (!ifindex) {
			usernic_error("Failed to get netdev index: %s.\n", strerror(errno));
			goto do_full_cleanup;
		}
	}

	ret = lxc_netdev_rename_by_name(oldname, *newnamep);
	if (ret < 0) {
		usernic_error("Error %d renaming netdev %s to %s in container.\n", ret, oldname, *newnamep);
		goto do_full_cleanup;
	}

	if (grab_newname) {
		char ifname[IFNAMSIZ];
		char *namep = ifname;

		if (!if_indextoname(ifindex, namep)) {
			usernic_error("Failed to get new netdev name: %s.\n", strerror(errno));
			goto do_full_cleanup;
		}

		*newnamep = strdup(namep);
		if (!*newnamep)
			goto do_full_cleanup;
	}

	fret = 0;

do_full_cleanup:
	ret = setresuid(ruid, euid, suid);
	if (ret < 0) {
		usernic_error("Failed to restore privilege by setting effective "
			      "user id to %d, real user id to %d, and saved user "
			      "ID to %d: %s.\n",
			      ruid, euid, suid, strerror(errno));
		fret = -1;
		// COMMENT(brauner): setns() should fail if setresuid() doesn't
		// succeed but there's no harm in falling through; keeps the
		// code cleaner.
	}

	ret = setns(ofd, CLONE_NEWNET);
	if (ret < 0) {
		usernic_error("Failed to setns() to original network namespace "
			      "of PID %d: %s.\n",
			      ofd, strerror(errno));
		fret = -1;
	}

do_partial_cleanup:
	if (fd >= 0)
		close(fd);
	close(ofd);

	return fret;
}

/*
 * If the caller (real uid, not effective uid) may read the
 * /proc/[pid]/ns/net, then it is either the caller's netns or one
 * which it created.
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
			      "ID to %d: %s.\n",
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
			      "to %d, and saved user ID to %d: %s.\n",
			      ruid, euid, suid, strerror(errno));
		may_access = false;
	}

	return may_access;
}

int main(int argc, char *argv[])
{
	int n, fd;
	char *me;
	char *nicname;
	int pid;
	char *cnic = NULL; /* Created nic name in container is returned here. */
	char *vethname = NULL;
	bool gotone = false;
	struct alloted_s *alloted = NULL;

	nicname = alloca(40);
	if (!nicname) {
		usernic_error("Failed allocate memory: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* set a sane env, because we are setuid-root */
	if (clearenv() < 0) {
		usernic_error("%s", "Failed to clear environment.\n");
		exit(EXIT_FAILURE);
	}
	if (setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1) < 0) {
		usernic_error("%s", "Failed to set PATH, exiting.\n");
		exit(EXIT_FAILURE);
	}
	if ((me = get_username()) == NULL) {
		usernic_error("%s", "Failed to get username.\n");
		exit(EXIT_FAILURE);
	}

	if (argc < 6)
		usage(argv[0], true);

	if (argc >= 7)
		vethname = argv[6];

	lxcpath = argv[1];
	lxcname = argv[2];

	errno = 0;
	pid = strtol(argv[3], NULL, 10);
	if (errno) {
		usernic_error("Could not read pid: %s.\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	if (!create_db_dir(LXC_USERNIC_DB)) {
		usernic_error("%s", "Failed to create directory for db file.\n");
		exit(EXIT_FAILURE);
	}

	if ((fd = open_and_lock(LXC_USERNIC_DB)) < 0) {
		usernic_error("Failed to lock %s.\n", LXC_USERNIC_DB);
		exit(EXIT_FAILURE);
	}

	if (!may_access_netns(pid)) {
		usernic_error("User %s may not modify netns for pid %d.\n", me, pid);
		exit(EXIT_FAILURE);
	}

	n = get_alloted(me, argv[4], argv[5], &alloted);
	if (n > 0)
		gotone = get_nic_if_avail(fd, alloted, pid, argv[4], argv[5], n, &nicname, &cnic);

	close(fd);
	free_alloted(&alloted);
	if (!gotone) {
		usernic_error("%s", "Quota reached.\n");
		exit(EXIT_FAILURE);
	}

	/* Now rename the link. */
	if (rename_in_ns(pid, cnic, &vethname) < 0) {
		usernic_error("%s", "Failed to rename the link.\n");
		if (lxc_netdev_delete_by_name(cnic) < 0)
			usernic_error("Failed to delete link \"%s\" the link. Manual cleanup needed.\n", cnic);
		exit(EXIT_FAILURE);
	}

	/* Write the name of the interface pair to the stdout - like
	 * eth0:veth9MT2L4.
	 */
	fprintf(stdout, "%s:%s\n", vethname, nicname);
	exit(EXIT_SUCCESS);
}
