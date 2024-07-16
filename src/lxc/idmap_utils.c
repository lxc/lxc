/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>

#include "lxc.h"

#include "log.h"
#include "lxclock.h"
#include "memory_utils.h"
#include "utils.h"

lxc_log_define(idmap_utils, lxc);

int write_id_mapping(enum idtype idtype, pid_t pid, const char *buf,
		     size_t buf_size)
{
	__do_close int fd = -EBADF;
	int ret;
	char path[PATH_MAX];

	if (geteuid() != 0 && idtype == ID_TYPE_GID) {
		__do_close int setgroups_fd = -EBADF;

		ret = strnprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
		if (ret < 0)
			return -E2BIG;

		setgroups_fd = open(path, O_WRONLY);
		if (setgroups_fd < 0 && errno != ENOENT)
			return log_error_errno(-1, errno, "Failed to open \"%s\"", path);

		if (setgroups_fd >= 0) {
			ret = lxc_write_nointr(setgroups_fd, "deny\n",
					       STRLITERALLEN("deny\n"));
			if (ret != STRLITERALLEN("deny\n"))
				return log_error_errno(-1, errno, "Failed to write \"deny\" to \"/proc/%d/setgroups\"", pid);
			TRACE("Wrote \"deny\" to \"/proc/%d/setgroups\"", pid);
		}
	}

	ret = strnprintf(path, sizeof(path), "/proc/%d/%cid_map", pid,
		       idtype == ID_TYPE_UID ? 'u' : 'g');
	if (ret < 0)
		return -E2BIG;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return log_error_errno(-1, errno, "Failed to open \"%s\"", path);

	ret = lxc_write_nointr(fd, buf, buf_size);
	if (ret < 0 || (size_t)ret != buf_size)
		return log_error_errno(-1, errno, "Failed to write %cid mapping to \"%s\"",
				       idtype == ID_TYPE_UID ? 'u' : 'g', path);

	return 0;
}

/* Check whether a binary exist and has either CAP_SETUID, CAP_SETGID or both.
 *
 * @return  1      if functional binary was found
 * @return  0      if binary exists but is lacking privilege
 * @return -ENOENT if binary does not exist
 * @return -EINVAL if cap to check is neither CAP_SETUID nor CAP_SETGID
 */
static int idmaptool_on_path_and_privileged(const char *binary, cap_value_t cap)
{
	__do_free char *path = NULL;
	int ret;
	struct stat st;

	if (cap != CAP_SETUID && cap != CAP_SETGID)
		return ret_errno(EINVAL);

	path = on_path(binary, NULL);
	if (!path)
		return ret_errno(ENOENT);

	ret = stat(path, &st);
	if (ret < 0)
		return -errno;

	/* Check if the binary is setuid. */
	if (st.st_mode & S_ISUID)
		return log_debug(1, "The binary \"%s\" does have the setuid bit set", path);

#if HAVE_LIBCAP && LIBCAP_SUPPORTS_FILE_CAPABILITIES
	/* Check if it has the CAP_SETUID capability. */
	if ((cap & CAP_SETUID) &&
	    lxc_file_cap_is_set(path, CAP_SETUID, CAP_EFFECTIVE) &&
	    lxc_file_cap_is_set(path, CAP_SETUID, CAP_PERMITTED))
		return log_debug(1, "The binary \"%s\" has CAP_SETUID in its CAP_EFFECTIVE and CAP_PERMITTED sets", path);

	/* Check if it has the CAP_SETGID capability. */
	if ((cap & CAP_SETGID) &&
	    lxc_file_cap_is_set(path, CAP_SETGID, CAP_EFFECTIVE) &&
	    lxc_file_cap_is_set(path, CAP_SETGID, CAP_PERMITTED))
		return log_debug(1, "The binary \"%s\" has CAP_SETGID in its CAP_EFFECTIVE and CAP_PERMITTED sets", path);

	return 0;
#else
	/*
	 * If we cannot check for file capabilities we need to give the benefit
	 * of the doubt. Otherwise we might fail even though all the necessary
	 * file capabilities are set.
	 */
	DEBUG("Cannot check for file capabilities as full capability support is missing. Manual intervention needed");
	return 1;
#endif
}

static int lxc_map_ids_exec_wrapper(void *args)
{
	execl("/bin/sh", "sh", "-c", (char *)args, (char *)NULL);
	return -1;
}

static struct id_map *find_mapped_hostid_entry(const struct list_head *idmap,
					       unsigned id, enum idtype idtype);

int lxc_map_ids(struct list_head *idmap, pid_t pid)
{
	int fill, left;
	uid_t hostuid;
	gid_t hostgid;
	char u_or_g;
	char *pos;
	char cmd_output[PATH_MAX];
	struct id_map *map;
	enum idtype type;
	int ret = 0, gidmap = 0, uidmap = 0;
	char mapbuf[STRLITERALLEN("new@idmap") + STRLITERALLEN(" ") +
		    INTTYPE_TO_STRLEN(pid_t) + STRLITERALLEN(" ") +
		    LXC_IDMAPLEN] = {0};
	bool had_entry = false, maps_host_root = false, use_shadow = false;

	hostuid = geteuid();
	hostgid = getegid();

	/*
	 * Check whether caller wants to map host root.
	 * Due to a security fix newer kernels require CAP_SETFCAP when mapping
	 * host root into the child userns as you would be able to write fscaps
	 * that would be valid in the ancestor userns. Mapping host root should
	 * rarely be the case but LXC is being clever in a bunch of cases.
	 */
	if (find_mapped_hostid_entry(idmap, 0, ID_TYPE_UID))
		maps_host_root = true;

	/* If new{g,u}idmap exists, that is, if shadow is handing out subuid
	 * ranges, then insist that root also reserve ranges in subuid. This
	 * will protected it by preventing another user from being handed the
	 * range by shadow.
	 */
	uidmap = idmaptool_on_path_and_privileged("newuidmap", CAP_SETUID);
	if (uidmap == -ENOENT)
		INFO("newuidmap binary is missing");
	else if (!uidmap)
		WARN("newuidmap is lacking necessary privileges");

	gidmap = idmaptool_on_path_and_privileged("newgidmap", CAP_SETGID);
	if (gidmap == -ENOENT)
		INFO("newgidmap binary is missing");
	else if (!gidmap)
		WARN("newgidmap is lacking necessary privileges");

	if (maps_host_root) {
		INFO("Caller maps host root. Writing mapping directly");
	} else if (uidmap > 0 && gidmap > 0) {
		DEBUG("Functional newuidmap and newgidmap binary found");
		use_shadow = true;
	} else {
		/* In case unprivileged users run application containers via
		 * execute() or a start*() there are valid cases where they may
		 * only want to map their own {g,u}id. Let's not block them from
		 * doing so by requiring geteuid() == 0.
		 */
		DEBUG("No newuidmap and newgidmap binary found. Trying to "
		      "write directly with euid %d", hostuid);
	}

	/* Check if we really need to use newuidmap and newgidmap.
	* If the user is only remapping their own {g,u}id, we don't need it.
	*/
	if (use_shadow && list_len(map, idmap, head) == 2) {
		use_shadow = false;
		list_for_each_entry(map, idmap, head) {
			if (map->idtype == ID_TYPE_UID && map->range == 1 &&
			    map->nsid == hostuid && map->hostid == hostuid)
				continue;
			if (map->idtype == ID_TYPE_GID && map->range == 1 &&
			    map->nsid == hostgid && map->hostid == hostgid)
				continue;
			use_shadow = true;
			break;
		}
	}

	for (type = ID_TYPE_UID, u_or_g = 'u'; type <= ID_TYPE_GID;
	     type++, u_or_g = 'g') {
		pos = mapbuf;

		if (use_shadow)
			pos += sprintf(mapbuf, "new%cidmap %d", u_or_g, pid);

		list_for_each_entry(map, idmap, head) {
			if (map->idtype != type)
				continue;

			had_entry = true;

			left = LXC_IDMAPLEN - (pos - mapbuf);
			fill = strnprintf(pos, left, "%s%lu %lu %lu%s",
					use_shadow ? " " : "", map->nsid,
					map->hostid, map->range,
					use_shadow ? "" : "\n");
			/*
			 * The kernel only takes <= 4k for writes to
			 * /proc/<pid>/{g,u}id_map
			 */
			if (fill <= 0)
				return log_error_errno(-1, errno, "Too many %cid mappings defined", u_or_g);

			pos += fill;
		}
		if (!had_entry)
			continue;

		/* Try to catch the output of new{g,u}idmap to make debugging
		 * easier.
		 */
		if (use_shadow) {
			ret = run_command(cmd_output, sizeof(cmd_output),
					  lxc_map_ids_exec_wrapper,
					  (void *)mapbuf);
			if (ret < 0)
				return log_error(-1, "new%cidmap failed to write mapping \"%s\": %s", u_or_g, cmd_output, mapbuf);
			TRACE("new%cidmap wrote mapping \"%s\"", u_or_g, mapbuf);
		} else {
			ret = write_id_mapping(type, pid, mapbuf, pos - mapbuf);
			if (ret < 0)
				return log_error(-1, "Failed to write mapping: %s", mapbuf);
			TRACE("Wrote mapping \"%s\"", mapbuf);
		}

		memset(mapbuf, 0, sizeof(mapbuf));
	}

	return 0;
}

int mapped_hostid(unsigned id, const struct lxc_conf *conf, enum idtype idtype)
{
	struct id_map *map;

	list_for_each_entry(map, &conf->id_map, head) {
		if (map->idtype != idtype)
			continue;

		if (id >= map->hostid && id < map->hostid + map->range)
			return (id - map->hostid) + map->nsid;
	}

	return -1;
}

int find_unmapped_nsid(const struct lxc_conf *conf, enum idtype idtype)
{
	struct id_map *map;
	unsigned int freeid = 0;

again:
	list_for_each_entry(map, &conf->id_map, head) {
		if (map->idtype != idtype)
			continue;

		if (freeid >= map->nsid && freeid < map->nsid + map->range) {
			freeid = map->nsid + map->range;
			goto again;
		}
	}

	return freeid;
}

static const struct id_map *find_mapped_nsid_entry(const struct lxc_conf *conf,
						   unsigned id,
						   enum idtype idtype)
{
	struct id_map *map;
	struct id_map *retmap = NULL;

	/* Shortcut for container's root mappings. */
	if (id == 0) {
		if (idtype == ID_TYPE_UID)
			return conf->root_nsuid_map;

		if (idtype == ID_TYPE_GID)
			return conf->root_nsgid_map;
	}

	list_for_each_entry(map, &conf->id_map, head) {
		if (map->idtype != idtype)
			continue;

		if (id >= map->nsid && id < map->nsid + map->range) {
			retmap = map;
			break;
		}
	}

	return retmap;
}

struct id_map *mapped_nsid_add(const struct lxc_conf *conf, unsigned id,
				      enum idtype idtype)
{
	const struct id_map *map;
	struct id_map *retmap;

	map = find_mapped_nsid_entry(conf, id, idtype);
	if (!map)
		return NULL;

	retmap = zalloc(sizeof(*retmap));
	if (!retmap)
		return NULL;

	memcpy(retmap, map, sizeof(*retmap));
	return retmap;
}

static struct id_map *find_mapped_hostid_entry(const struct list_head *idmap,
					       unsigned id, enum idtype idtype)
{
	struct id_map *retmap = NULL;
	struct id_map *map;

	list_for_each_entry(map, idmap, head) {
		if (map->idtype != idtype)
			continue;

		if (id >= map->hostid && id < map->hostid + map->range) {
			retmap = map;
			break;
		}
	}

	return retmap;
}

/* Allocate a new {g,u}id mapping for the given {g,u}id. Re-use an already
 * existing one or establish a new one.
 */
struct id_map *mapped_hostid_add(const struct lxc_conf *conf, uid_t id,
					enum idtype type)
{
	__do_free struct id_map *entry = NULL;
	int hostid_mapped;
	struct id_map *tmp = NULL;

	entry = zalloc(sizeof(*entry));
	if (!entry)
		return NULL;

	/* Reuse existing mapping. */
	tmp = find_mapped_hostid_entry(&conf->id_map, id, type);
	if (tmp) {
		memcpy(entry, tmp, sizeof(*entry));
	} else {
		/* Find new mapping. */
		hostid_mapped = find_unmapped_nsid(conf, type);
		if (hostid_mapped < 0)
			return log_debug(NULL, "Failed to find free mapping for id %d", id);

		entry->idtype = type;
		entry->nsid = hostid_mapped;
		entry->hostid = (unsigned long)id;
		entry->range = 1;
	}

	return move_ptr(entry);
}
