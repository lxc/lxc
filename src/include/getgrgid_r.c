/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2018 Canonical Ltd.
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
 *
 * This function has been copied from musl.
 */

#define _GNU_SOURCE
#include <byteswap.h>
#include <errno.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>

#define LOGIN_NAME_MAX 256
#define NSCDVERSION 2
#define GETPWBYNAME 0
#define GETPWBYUID 1
#define GETGRBYNAME 2
#define GETGRBYGID 3
#define GETINITGR 15

#define REQVERSION 0
#define REQTYPE 1
#define REQKEYLEN 2
#define REQ_LEN 3

#define PWVERSION 0
#define PWFOUND 1
#define PWNAMELEN 2
#define PWPASSWDLEN 3
#define PWUID 4
#define PWGID 5
#define PWGECOSLEN 6
#define PWDIRLEN 7
#define PWSHELLLEN 8
#define PW_LEN 9

#define GRVERSION 0
#define GRFOUND 1
#define GRNAMELEN 2
#define GRPASSWDLEN 3
#define GRGID 4
#define GRMEMCNT 5
#define GR_LEN 6

#define INITGRVERSION 0
#define INITGRFOUND 1
#define INITGRNGRPS 2
#define INITGR_LEN 3

#define FIX(x) (gr->gr_##x = gr->gr_##x - line + buf)

static unsigned atou(char **s)
{
	unsigned x;
	for (x = 0; **s - '0' < 10U; ++*s)
		x = 10 * x + (**s - '0');
	return x;
}

static int __getgrent_a(FILE *f, struct group *gr, char **line, size_t *size,
			char ***mem, size_t *nmem, struct group **res)
{
	ssize_t l;
	char *s, *mems;
	size_t i;
	int rv = 0;

#ifdef HAVE_PTHREAD_SETCANCELSTATE
	int cs;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
#endif

	for (;;) {
		if ((l = getline(line, size, f)) < 0) {
			rv = ferror(f) ? errno : 0;
			free(*line);
			*line = 0;
			gr = 0;
			goto end;
		}
		line[0][l - 1] = 0;

		s = line[0];
		gr->gr_name = s++;
		if (!(s = strchr(s, ':')))
			continue;

		*s++ = 0;
		gr->gr_passwd = s;
		if (!(s = strchr(s, ':')))
			continue;

		*s++ = 0;
		gr->gr_gid = atou(&s);
		if (*s != ':')
			continue;

		*s++ = 0;
		mems = s;
		break;
	}

	for (*nmem = !!*s; *s; s++)
		if (*s == ',')
			++*nmem;
	free(*mem);
	*mem = calloc(sizeof(char *), *nmem + 1);
	if (!*mem) {
		rv = errno;
		free(*line);
		*line = 0;
		gr = 0;
		goto end;
	}
	if (*mems) {
		mem[0][0] = mems;
		for (s = mems, i = 0; *s; s++)
			if (*s == ',')
				*s++ = 0, mem[0][++i] = s;
		mem[0][++i] = 0;
	} else {
		mem[0][0] = 0;
	}
	gr->gr_mem = *mem;
end:

#ifdef HAVE_PTHREAD_SETCANCELSTATE
	pthread_setcancelstate(cs, 0);
#endif

	*res = gr;
	if (rv)
		errno = rv;
	return rv;
}

static char *itoa(char *p, uint32_t x)
{
	// number of digits in a uint32_t + NUL
	p += 11;
	*--p = 0;
	do {
		*--p = '0' + x % 10;
		x /= 10;
	} while (x);
	return p;
}

static const struct {
	short sun_family;
	char sun_path[21];
} addr = {AF_UNIX, "/var/run/nscd/socket"};

static FILE *__nscd_query(int32_t req, const char *key, int32_t *buf,
			  size_t len, int *swap)
{
	size_t i;
	int fd;
	FILE *f = 0;
	int32_t req_buf[REQ_LEN] = {NSCDVERSION, req,
				    strnlen(key, LOGIN_NAME_MAX) + 1};
	struct msghdr msg = {.msg_iov =
				 (struct iovec[]){{&req_buf, sizeof(req_buf)},
						  {(char *)key, strlen(key) + 1}},
			     .msg_iovlen = 2};
	int errno_save = errno;

	*swap = 0;
retry:
	memset(buf, 0, len);
	buf[0] = NSCDVERSION;

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return NULL;

	if (!(f = fdopen(fd, "r"))) {
		close(fd);
		return 0;
	}

	if (req_buf[2] > LOGIN_NAME_MAX)
		return f;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* If there isn't a running nscd we simulate a "not found"
		 * result and the caller is responsible for calling
		 * fclose on the (unconnected) socket. The value of
		 * errno must be left unchanged in this case.  */
		if (errno == EACCES || errno == ECONNREFUSED || errno == ENOENT) {
			errno = errno_save;
			return f;
		}
		goto error;
	}

	if (sendmsg(fd, &msg, MSG_NOSIGNAL) < 0)
		goto error;

	if (!fread(buf, len, 1, f)) {
		/* If the VERSION entry mismatches nscd will disconnect. The
		 * most likely cause is that the endianness mismatched. So, we
		 * byteswap and try once more. (if we already swapped, just
		 * fail out)
		 */
		if (ferror(f))
			goto error;
		if (!*swap) {
			fclose(f);
			for (i = 0; i < sizeof(req_buf) / sizeof(req_buf[0]);
			     i++) {
				req_buf[i] = bswap_32(req_buf[i]);
			}
			*swap = 1;
			goto retry;
		} else {
			errno = EIO;
			goto error;
		}
	}

	if (*swap) {
		for (i = 0; i < len / sizeof(buf[0]); i++) {
			buf[i] = bswap_32(buf[i]);
		}
	}

	/* The first entry in every nscd response is the version number. This
	 * really shouldn't happen, and is evidence of some form of malformed
	 * response.
	 */
	if (buf[0] != NSCDVERSION) {
		errno = EIO;
		goto error;
	}

	return f;
error:
	fclose(f);
	return 0;
}

static int __getgr_a(const char *name, gid_t gid, struct group *gr, char **buf,
		     size_t *size, char ***mem, size_t *nmem, struct group **res)
{
	FILE *f;
	int rv = 0;
#ifdef HAVE_PTHREAD_SETCANCELSTATE
	int cs;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
#endif

	*res = 0;

	f = fopen("/etc/group", "rbe");
	if (!f) {
		rv = errno;
		goto done;
	}

	while (!(rv = __getgrent_a(f, gr, buf, size, mem, nmem, res)) && *res) {
		if ((name && !strcmp(name, (*res)->gr_name)) ||
		    (!name && (*res)->gr_gid == gid)) {
			break;
		}
	}
	fclose(f);

	if (!*res && (rv == 0 || rv == ENOENT || rv == ENOTDIR)) {
		int32_t req = name ? GETGRBYNAME : GETGRBYGID;
		int32_t i;
		const char *key;
		int32_t groupbuf[GR_LEN] = {0};
		size_t len = 0;
		size_t grlist_len = 0;
		char gidbuf[11] = {0};
		int swap = 0;
		char *ptr;

		if (name) {
			key = name;
		} else {
			if (gid < 0 || gid > UINT32_MAX) {
				rv = 0;
				goto done;
			}
			key = itoa(gidbuf, gid);
		}

		f = __nscd_query(req, key, groupbuf, sizeof groupbuf, &swap);
		if (!f) {
			rv = errno;
			goto done;
		}

		if (!groupbuf[GRFOUND]) {
			rv = 0;
			goto cleanup_f;
		}

		if (!groupbuf[GRNAMELEN] || !groupbuf[GRPASSWDLEN]) {
			rv = EIO;
			goto cleanup_f;
		}

		if ((int64_t)groupbuf[GRNAMELEN] >
		    (int64_t)(SIZE_MAX - groupbuf[GRPASSWDLEN])) {
			rv = ENOMEM;
			goto cleanup_f;
		}
		len = groupbuf[GRNAMELEN] + groupbuf[GRPASSWDLEN];

		for (i = 0; i < groupbuf[GRMEMCNT]; i++) {
			uint32_t name_len;
			if (fread(&name_len, sizeof name_len, 1, f) < 1) {
				rv = ferror(f) ? errno : EIO;
				goto cleanup_f;
			}
			if (swap) {
				name_len = bswap_32(name_len);
			}
			if (name_len > SIZE_MAX - grlist_len ||
			    name_len > SIZE_MAX - len) {
				rv = ENOMEM;
				goto cleanup_f;
			}
			len += name_len;
			grlist_len += name_len;
		}

		if (len > *size || !*buf) {
			char *tmp = realloc(*buf, len);
			if (!tmp) {
				rv = errno;
				goto cleanup_f;
			}
			*buf = tmp;
			*size = len;
		}

		if (!fread(*buf, len, 1, f)) {
			rv = ferror(f) ? errno : EIO;
			goto cleanup_f;
		}

		if (((size_t)(groupbuf[GRMEMCNT] + 1)) > *nmem) {
			if (((size_t)(groupbuf[GRMEMCNT] + 1)) >
			    (SIZE_MAX / sizeof(char *))) {
				rv = ENOMEM;
				goto cleanup_f;
			}
			char **tmp = realloc(*mem, (groupbuf[GRMEMCNT] + 1) *
						       sizeof(char *));
			if (!tmp) {
				rv = errno;
				goto cleanup_f;
			}
			*mem = tmp;
			*nmem = groupbuf[GRMEMCNT] + 1;
		}

		if (groupbuf[GRMEMCNT]) {
			mem[0][0] =
			    *buf + groupbuf[GRNAMELEN] + groupbuf[GRPASSWDLEN];
			for (ptr = mem[0][0], i = 0;
			     ptr != mem[0][0] + grlist_len; ptr++)
				if (!*ptr)
					mem[0][++i] = ptr + 1;
			mem[0][i] = 0;

			if (i != groupbuf[GRMEMCNT]) {
				rv = EIO;
				goto cleanup_f;
			}
		} else {
			mem[0][0] = 0;
		}

		gr->gr_name = *buf;
		gr->gr_passwd = gr->gr_name + groupbuf[GRNAMELEN];
		gr->gr_gid = groupbuf[GRGID];
		gr->gr_mem = *mem;

		if (gr->gr_passwd[-1] ||
		    gr->gr_passwd[groupbuf[GRPASSWDLEN] - 1]) {
			rv = EIO;
			goto cleanup_f;
		}

		if ((name && strcmp(name, gr->gr_name)) ||
		    (!name && gid != gr->gr_gid)) {
			rv = EIO;
			goto cleanup_f;
		}

		*res = gr;

	cleanup_f:
		fclose(f);
		goto done;
	}

done:

#ifdef HAVE_PTHREAD_SETCANCELSTATE
	pthread_setcancelstate(cs, 0);
#endif

	if (rv)
		errno = rv;
	return rv;
}

static int getgr_r(const char *name, gid_t gid, struct group *gr, char *buf,
		   size_t size, struct group **res)
{
	char *line = 0;
	size_t len = 0;
	char **mem = 0;
	size_t nmem = 0;
	int rv = 0;
	size_t i;

#ifdef HAVE_PTHREAD_SETCANCELSTATE
	int cs;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
#endif

	rv = __getgr_a(name, gid, gr, &line, &len, &mem, &nmem, res);
	if (*res && size < len + (nmem + 1) * sizeof(char *) + 32) {
		*res = 0;
		rv = ERANGE;
	}
	if (*res) {
		buf += (16 - (uintptr_t)buf) % 16;
		gr->gr_mem = (void *)buf;
		buf += (nmem + 1) * sizeof(char *);
		memcpy(buf, line, len);
		FIX(name);
		FIX(passwd);
		for (i = 0; mem[i]; i++)
			gr->gr_mem[i] = mem[i] - line + buf;
		gr->gr_mem[i] = 0;
	}
	free(mem);
	free(line);

#ifdef HAVE_PTHREAD_SETCANCELSTATE
	pthread_setcancelstate(cs, 0);
#endif

	if (rv)
		errno = rv;
	return rv;
}

int getgrgid_r(gid_t gid, struct group *gr, char *buf, size_t size, struct group **res)
{
	return getgr_r(0, gid, gr, buf, size, res);
}
