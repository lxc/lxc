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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <alloca.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/param.h>

#include "config.h"
#include "utils.h"
#include "network.h"

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
		fprintf(stderr, "Failed to open %s: %s\n",
			path, strerror(errno));
		return(fd);
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;
	if (fcntl(fd, F_SETLKW, &lk) < 0) {
		fprintf(stderr, "Failed to lock %s: %s\n",
			path, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}


static char *get_username(void)
{
	struct passwd *pwd = getpwuid(getuid());

	if (pwd == NULL) {
		perror("getpwuid");
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

	if (ngroups == -1) {
		fprintf(stderr, "Failed to get number of groups user belongs to: %s\n", strerror(errno));
		return NULL;
	}
	if (ngroups == 0)
		return NULL;

	group_ids = (gid_t *)malloc(sizeof(gid_t)*ngroups);

	if (group_ids == NULL) {
		fprintf(stderr, "Out of memory while getting groups the user belongs to\n");
		return NULL;
	}

	ret = getgroups(ngroups, group_ids);

	if (ret < 0) {
		free(group_ids);
		fprintf(stderr, "Failed to get process groups: %s\n", strerror(errno));
		return NULL;
	}

	groupnames = (char **)malloc(sizeof(char *)*(ngroups+1));

	if (groupnames == NULL) {
		free(group_ids);
		fprintf(stderr, "Out of memory while getting group names\n");
		return NULL;
	}

	memset(groupnames, 0, sizeof(char *)*(ngroups+1));

	for (i=0; i<ngroups; i++ ) {
		gr = getgrgid(group_ids[i]);

		if (gr == NULL) {
			fprintf(stderr, "Failed to get group name\n");
			free(group_ids);
			free_groupnames(groupnames);
			return NULL;
		}

		groupnames[i] = strdup(gr->gr_name);

		if (groupnames[i] == NULL) {
			fprintf(stderr, "Failed to copy group name: %s", gr->gr_name);
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
	while (groupnames != NULL) {
		if (strcmp(name, *groupnames) == 0)
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

	if (head == NULL || name == NULL) {
		// sanity check. parameters should not be null
		fprintf(stderr, "NULL parameters to append_alloted not allowed\n");
		return NULL;
	}

	al = (struct alloted_s *)malloc(sizeof(struct alloted_s));

	if (al == NULL) {
		// unable to allocate memory to new struct
		fprintf(stderr, "Out of memory in append_alloted\n");
		return NULL;
	}

	al->name = strdup(name);

	if (al->name == NULL) {
		free(al);
		return NULL;
	}

	al->allowed = n;
	al->next = NULL;

	if (*head == NULL) {
		*head = al;
		return al;
	}

	cur = *head;
	while (cur->next != NULL)
		cur = cur->next;

	cur->next = al;
	return al;
}

static void free_alloted(struct alloted_s **head)
{
	struct alloted_s *cur;

	if (head == NULL) {
		return;
	}

	cur = *head;

	while (cur != NULL) {
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
	FILE *fin = fopen(LXC_USERNIC_CONF, "r");
	char *line = NULL;
	char name[100], type[100], br[100];
	size_t len = 0;
	int n, ret, count = 0;
	char **groups;

	if (!fin) {
		fprintf(stderr, "Failed to open %s: %s\n", LXC_USERNIC_CONF,
			strerror(errno));
		return -1;
	}

	groups = get_groupnames();
	while ((getline(&line, &len, fin)) != -1) {
		ret = sscanf(line, "%99[^ \t] %99[^ \t] %99[^ \t] %d", name, type, br, &n);

		if (ret != 4)
			continue;

		if (strlen(name) == 0)
			continue;

		if (strcmp(name, me) != 0)
		{
			if (name[0] != '@')
				continue;
			if (!name_is_in_groupnames(name+1, groups))
				continue;
		}
		if (strcmp(type, intype) != 0)
			continue;
		if (strcmp(link, br) != 0)
			continue;

		/* found the user or group with the appropriate settings, therefore finish the search.
		 * what to do if there are more than one applicable lines? not specified in the docs.
		 * since getline is implemented with realloc, we don't need to free line until exiting func.
		 *
		 * if append_alloted returns NULL, e.g. due to a malloc error, we set count to 0 and break the loop,
		 * allowing cleanup and then exiting from main()
		 */
		if (append_alloted(alloted, name, n) == NULL) {
			count = 0;
			break;
		}
		count += n;
	}

	free_groupnames(groups);
	fclose(fin);
	free(line);

	// now return the total number of nics that this user can create
	return count;
}

static char *get_eol(char *s, char *e)
{
	while (s<e && *s && *s != '\n')
		s++;
	return s;
}

static char *get_eow(char *s, char *e)
{
	while (s<e && *s && !isblank(*s) && *s != '\n')
		s++;
	return s;
}

static char *find_line(char *p, char *e, char *u, char *t, char *l)
{
	char *p1, *p2, *ret;

	while (p<e  && (p1 = get_eol(p, e)) < e) {
		ret = p;
		if (*p == '#')
			goto next;
		while (p<e && isblank(*p)) p++;
		p2 = get_eow(p, e);
		if (!p2 || p2-p != strlen(u) || strncmp(p, u, strlen(u)) != 0)
			goto next;
		p = p2+1;
		while (p<e && isblank(*p)) p++;
		p2 = get_eow(p, e);
		if (!p2 || p2-p != strlen(t) || strncmp(p, t, strlen(t)) != 0)
			goto next;
		p = p2+1;
		while (p<e && isblank(*p)) p++;
		p2 = get_eow(p, e);
		if (!p2 || p2-p != strlen(l) || strncmp(p, l, strlen(l)) != 0)
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

	if (strcmp(nic, "none") == 0)
		return true;
	ret = snprintf(path, MAXPATHLEN, "/sys/class/net/%s", nic);
	if (ret < 0 || ret >= MAXPATHLEN) // should never happen!
		return false;
	ret = stat(path, &sb);
	if (ret != 0)
		return false;
	return true;
}

static int instantiate_veth(char *n1, char **n2)
{
	int err;

	err = snprintf(*n2, IFNAMSIZ, "%sp", n1);
	if (err < 0 || err >= IFNAMSIZ) {
		fprintf(stderr, "nic name too long\n");
		return -1;
	}

	err = lxc_veth_create(n1, *n2);
	if (err) {
		fprintf(stderr, "failed to create %s-%s : %s\n", n1, *n2,
		      strerror(-err));
		return -1;
	}

	/* changing the high byte of the mac address to 0xfe, the bridge interface
	 * will always keep the host's mac address and not take the mac address
	 * of a container */
	err = setup_private_host_hw_addr(n1);
	if (err) {
		fprintf(stderr, "failed to change mac address of host interface '%s' : %s\n",
			n1, strerror(-err));
	}

	return netdev_set_flag(n1, IFF_UP);
}

static int get_mtu(char *name)
{
	int idx = if_nametoindex(name);
	return netdev_get_mtu(idx);
}

static bool create_nic(char *nic, char *br, int pid, char **cnic)
{
	char *veth1buf, *veth2buf;
	veth1buf = alloca(IFNAMSIZ);
	veth2buf = alloca(IFNAMSIZ);
	int ret, mtu;

	ret = snprintf(veth1buf, IFNAMSIZ, "%s", nic);
	if (ret < 0 || ret >= IFNAMSIZ) {
		fprintf(stderr, "host nic name too long\n");
		return false;
	}

	/* create the nics */
	if (instantiate_veth(veth1buf, &veth2buf) < 0) {
		fprintf(stderr, "Error creating veth tunnel\n");
		return false;
	}

	if (strcmp(br, "none") != 0) {
		/* copy the bridge's mtu to both ends */
		mtu = get_mtu(br);
		if (mtu != -1) {
			if (lxc_netdev_set_mtu(veth1buf, mtu) < 0 ||
					lxc_netdev_set_mtu(veth2buf, mtu) < 0) {
				fprintf(stderr, "Failed setting mtu\n");
				goto out_del;
			}
		}

		/* attach veth1 to bridge */
		if (lxc_bridge_attach(lxcpath, lxcname, br, veth1buf) < 0) {
			fprintf(stderr, "Error attaching %s to %s\n", veth1buf, br);
			goto out_del;
		}
	}

	/* pass veth2 to target netns */
	ret = lxc_netdev_move_by_name(veth2buf, pid, NULL);
	if (ret < 0) {
		fprintf(stderr, "Error moving %s to netns %d\n", veth2buf, pid);
		goto out_del;
	}
	*cnic = strdup(veth2buf);
	return true;

out_del:
	lxc_netdev_delete_by_name(veth1buf);
	return false;
}

/*
 * Get a new nic.
 * *dest will container the name (vethXXXXXX) which is attached
 * on the host to the lxc bridge
 */
static bool get_new_nicname(char **dest, char *br, int pid, char **cnic)
{
	char template[IFNAMSIZ];
	snprintf(template, sizeof(template), "vethXXXXXX");
	*dest = lxc_mkifname(template);

	if (!create_nic(*dest, br, pid, cnic)) {
		return false;
	}
	return true;
}

static bool get_nic_from_line(char *p, char **nic)
{
	char user[100], type[100], br[100];
	int ret;

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
	struct stat sb;
	char *buf, *p, *e, *nic;
	off_t len;
	struct entry_line *entry_lines = NULL;
	int i, n = 0;

	nic = alloca(100);

	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Failed to fstat: %s\n", strerror(errno));
		return false;
	}
	len = sb.st_size;
	if (len == 0)
		return true;
	buf = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "Failed to create mapping: %s\n", strerror(errno));
		return false;
	}

	p = buf;
	e = buf + len;
	while ((p = find_line(p, e, me, t, br)) != NULL) {
		struct entry_line *newe = realloc(entry_lines, sizeof(*entry_lines)*(n+1));
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
			entry_lines[n-1].keep = false;
		p += entry_lines[n-1].len + 1;
		if (p >= e)
			break;
 	}
	p = buf;
	for (i=0; i<n; i++) {
		if (!entry_lines[i].keep)
			continue;
		memcpy(p, entry_lines[i].start, entry_lines[i].len);
		p += entry_lines[i].len;
		*p = '\n';
		p++;
	}
	free(entry_lines);
	munmap(buf, sb.st_size);
	if (ftruncate(fd, p-buf))
		fprintf(stderr, "Failed to set new file size\n");
	return true;
}

static int count_entries(char *buf, off_t len, char *me, char *t, char *br)
{
	char *e = &buf[len];
	int count = 0;
	while ((buf = find_line(buf, e, me, t, br)) != NULL) {
		count++;
		buf = get_eol(buf, e)+1;
		if (buf >= e)
			break;
	}

	return count;
}

/*
 * The dbfile has lines of the format:
 * user type bridge nicname
 */
static bool get_nic_if_avail(int fd, struct alloted_s *names, int pid, char *intype, char *br, int allowed, char **nicname, char **cnic)
{
	off_t len, slen;
	struct stat sb;
	char *buf = NULL, *newline;
	int ret, count = 0;
	char *owner;
	struct alloted_s *n;

	for (n=names; n!=NULL; n=n->next)
		cull_entries(fd, n->name, intype, br);

	if (allowed == 0)
		return false;

	owner = names->name;

	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Failed to fstat: %s\n", strerror(errno));
		return false;
	}
	len = sb.st_size;
	if (len != 0) {
		buf = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if (buf == MAP_FAILED) {
			fprintf(stderr, "Failed to create mapping\n");
			return false;
		}

		owner = NULL;
		for (n=names; n!=NULL; n=n->next) {
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
	ret = snprintf(newline, slen, "%s %s %s %s\n", owner, intype, br, *nicname);
	if (ret < 0 || ret >= slen) {
		if (lxc_netdev_delete_by_name(*nicname) != 0)
			fprintf(stderr, "Error unlinking %s!\n", *nicname);
		return false;
	}
	if (len)
		munmap(buf, len);
	if (ftruncate(fd, len + slen))
		fprintf(stderr, "Failed to set new file size\n");
	buf = mmap(NULL, len + slen, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "Failed to create mapping after extending: %s\n", strerror(errno));
		if (lxc_netdev_delete_by_name(*nicname) != 0)
			fprintf(stderr, "Error unlinking %s!\n", *nicname);
		return false;
	}
	strcpy(buf+len, newline);
	munmap(buf, len+slen);
	return true;
}

static bool create_db_dir(char *fnam)
{
	char *p = alloca(strlen(fnam)+1);

	strcpy(p, fnam);
	fnam = p;
	p = p + 1;
again:
	while (*p && *p != '/') p++;
	if (!*p)
		return true;
	*p = '\0';
	if (mkdir(fnam, 0755) && errno != EEXIST) {
		fprintf(stderr, "failed to create %s\n", fnam);
		*p = '/';
		return false;
	}
	*(p++) = '/';
	goto again;
}

#define VETH_DEF_NAME "eth%d"

static int rename_in_ns(int pid, char *oldname, char **newnamep)
{
	char nspath[MAXPATHLEN];
	int fd = -1, ofd = -1, ret, ifindex = -1;
	bool grab_newname = false;

	ret = snprintf(nspath, MAXPATHLEN, "/proc/%d/ns/net", getpid());
	if (ret < 0 || ret >= MAXPATHLEN)
		return -1;
	if ((ofd = open(nspath, O_RDONLY)) < 0) {
		fprintf(stderr, "Opening %s\n", nspath);
		return -1;
	}
	ret = snprintf(nspath, MAXPATHLEN, "/proc/%d/ns/net", pid);
	if (ret < 0 || ret >= MAXPATHLEN)
		goto out_err;

	if ((fd = open(nspath, O_RDONLY)) < 0) {
		fprintf(stderr, "Opening %s\n", nspath);
		goto out_err;
	}
	if (setns(fd, 0) < 0) {
		fprintf(stderr, "setns to container network namespace\n");
		goto out_err;
	}
	close(fd); fd = -1;
	if (!*newnamep) {
		grab_newname = true;
		*newnamep = VETH_DEF_NAME;
		if (!(ifindex = if_nametoindex(oldname))) {
			fprintf(stderr, "failed to get netdev index\n");
			goto out_err;
		}
	}
	if ((ret = lxc_netdev_rename_by_name(oldname, *newnamep)) < 0) {
		fprintf(stderr, "Error %d renaming netdev %s to %s in container\n", ret, oldname, *newnamep);
		goto out_err;
	}
	if (grab_newname) {
		char ifname[IFNAMSIZ], *namep = ifname;
		if (!if_indextoname(ifindex, namep)) {
			fprintf(stderr, "Failed to get new netdev name\n");
			goto out_err;
		}
		*newnamep = strdup(namep);
		if (!*newnamep)
			goto out_err;
	}
	if (setns(ofd, 0) < 0) {
		fprintf(stderr, "Error returning to original netns\n");
		close(ofd);
		return -1;
	}
	close(ofd);

	return 0;

out_err:
	if (ofd >= 0)
		close(ofd);
	if (setns(ofd, 0) < 0)
		fprintf(stderr, "Error returning to original network namespace\n");
	if (fd >= 0)
		close(fd);
	return -1;
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
	if (ret) {
		fprintf(stderr, "Failed to get my uids: %s\n", strerror(errno));
		return false;
	}
	ret = setresuid(ruid, ruid, euid);
	if (ret) {
		fprintf(stderr, "Failed to set temp uids to (%d,%d,%d): %s\n",
				(int)ruid, (int)ruid, (int)euid, strerror(errno));
		return false;
	}
	ret = snprintf(s, 200, "/proc/%d/ns/net", pid);
	if (ret < 0 || ret >= 200)  // can't happen
		return false;
	ret = access(s, R_OK);
	if (ret) {
		fprintf(stderr, "Uid %d may not access %s: %s\n",
				(int)ruid, s, strerror(errno));
	}
	may_access = ret == 0;
	ret = setresuid(ruid, euid, suid);
	if (ret) {
		fprintf(stderr, "Failed to restore uids to (%d,%d,%d): %s\n",
				(int)ruid, (int)euid, (int)suid, strerror(errno));
		may_access = false;
	}
	return may_access;
}

int main(int argc, char *argv[])
{
	int n, fd;
	bool gotone = false;
	char *me;
	char *nicname = alloca(40);
	char *cnic = NULL; // created nic name in container is returned here.
	char *vethname = NULL;
	int pid;
	struct alloted_s *alloted = NULL;

	/* set a sane env, because we are setuid-root */
	if (clearenv() < 0) {
		fprintf(stderr, "Failed to clear environment");
		exit(1);
	}
	if (setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1) < 0) {
		fprintf(stderr, "Failed to set PATH, exiting\n");
		exit(1);
	}
	if ((me = get_username()) == NULL) {
		fprintf(stderr, "Failed to get username\n");
		exit(1);
	}

	if (argc < 6)
		usage(argv[0], true);
	if (argc >= 7)
		vethname = argv[6];

	lxcpath = argv[1];
	lxcname = argv[2];

	errno = 0;
	pid = (int) strtol(argv[3], NULL, 10);
	if (errno) {
		fprintf(stderr, "Could not read pid: %s\n", argv[1]);
		exit(1);
	}

	if (!create_db_dir(LXC_USERNIC_DB)) {
		fprintf(stderr, "Failed to create directory for db file\n");
		exit(1);
	}

	if ((fd = open_and_lock(LXC_USERNIC_DB)) < 0) {
		fprintf(stderr, "Failed to lock %s\n", LXC_USERNIC_DB);
		exit(1);
	}

	if (!may_access_netns(pid)) {
		fprintf(stderr, "User %s may not modify netns for pid %d\n",
			me, pid);
		exit(1);
	}

	n = get_alloted(me, argv[4], argv[5], &alloted);
	if (n > 0)
		gotone = get_nic_if_avail(fd, alloted, pid, argv[4], argv[5], n, &nicname, &cnic);

	close(fd);
	free_alloted(&alloted);
	if (!gotone) {
		fprintf(stderr, "Quota reached\n");
		exit(1);
	}

	// Now rename the link
	if (rename_in_ns(pid, cnic, &vethname) < 0) {
		fprintf(stderr, "Failed to rename the link\n");
		exit(1);
	}

	// write the name of the interface pair to the stdout - like eth0:veth9MT2L4
	fprintf(stdout, "%s:%s\n", vethname, nicname);
	exit(0);
}
