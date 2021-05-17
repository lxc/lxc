/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>

#include "af_unix.h"
#include "config.h"
#include "log.h"
#include "macro.h"
#include "memory_utils.h"
#include "process_utils.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(af_unix, lxc);

static ssize_t lxc_abstract_unix_set_sockaddr(struct sockaddr_un *addr,
					      const char *path)
{
	size_t len;

	if (!addr || !path)
		return ret_errno(EINVAL);

	/* Clear address structure */
	memset(addr, 0, sizeof(*addr));

	addr->sun_family = AF_UNIX;

	len = strlen(&path[1]);

	/* do not enforce \0-termination */
	if (len >= INT_MAX || len >= sizeof(addr->sun_path))
		return ret_errno(ENAMETOOLONG);

	/* do not enforce \0-termination */
	memcpy(&addr->sun_path[1], &path[1], len);
	return len;
}

int lxc_abstract_unix_open(const char *path, int type, int flags)
{
	__do_close int fd = -EBADF;
	int ret;
	ssize_t len;
	struct sockaddr_un addr;

	fd = socket(PF_UNIX, type | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	if (!path)
		return move_fd(fd);

	len = lxc_abstract_unix_set_sockaddr(&addr, path);
	if (len < 0)
		return -1;

	ret = bind(fd, (struct sockaddr *)&addr,
		   offsetof(struct sockaddr_un, sun_path) + len + 1);
	if (ret < 0)
		return -1;

	if (type == SOCK_STREAM) {
		ret = listen(fd, 100);
		if (ret < 0)
			return -1;
	}

	return move_fd(fd);
}

void lxc_abstract_unix_close(int fd)
{
	close(fd);
}

int lxc_abstract_unix_connect(const char *path)
{
	__do_close int fd = -EBADF;
	int ret;
	ssize_t len;
	struct sockaddr_un addr;

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	len = lxc_abstract_unix_set_sockaddr(&addr, path);
	if (len < 0)
		return -1;

	ret = connect(fd, (struct sockaddr *)&addr,
		      offsetof(struct sockaddr_un, sun_path) + len + 1);
	if (ret < 0)
		return -1;

	return move_fd(fd);
}

int lxc_abstract_unix_send_fds_iov(int fd, const int *sendfds, int num_sendfds,
				   struct iovec *const iov, size_t iovlen)
{
	__do_free char *cmsgbuf = NULL;
	int ret;
	struct msghdr msg = {};
	struct cmsghdr *cmsg = NULL;
	size_t cmsgbufsize = CMSG_SPACE(num_sendfds * sizeof(int));

	cmsgbuf = malloc(cmsgbufsize);
	if (!cmsgbuf)
		return ret_errno(-ENOMEM);

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = cmsgbufsize;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(num_sendfds * sizeof(int));

	msg.msg_controllen = cmsg->cmsg_len;

	memcpy(CMSG_DATA(cmsg), sendfds, num_sendfds * sizeof(int));

	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	do {
		ret = sendmsg(fd, &msg, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

int lxc_abstract_unix_send_fds(int fd, const int *sendfds, int num_sendfds,
			       void *data, size_t size)
{
	char buf[1] = {};
	struct iovec iov = {
		.iov_base	= data ? data : buf,
		.iov_len	= data ? size : sizeof(buf),
	};
	return lxc_abstract_unix_send_fds_iov(fd, sendfds, num_sendfds, &iov, 1);
}

int lxc_unix_send_fds(int fd, int *sendfds, int num_sendfds, void *data,
		      size_t size)
{
	return lxc_abstract_unix_send_fds(fd, sendfds, num_sendfds, data, size);
}

int __lxc_abstract_unix_send_two_fds(int fd, int fd_first, int fd_second,
				     void *data, size_t size)
{
	int fd_send[2] = {
		fd_first,
		fd_second,
	};
	return lxc_abstract_unix_send_fds(fd, fd_send, 2, data, size);
}

static ssize_t lxc_abstract_unix_recv_fds_iov(int fd,
					      struct unix_fds *ret_fds,
					      struct iovec *ret_iov,
					      size_t size_ret_iov)
{
	__do_free char *cmsgbuf = NULL;
	ssize_t ret;
	struct msghdr msg = {};
	struct cmsghdr *cmsg = NULL;
	size_t cmsgbufsize = CMSG_SPACE(sizeof(struct ucred)) +
			     CMSG_SPACE(ret_fds->fd_count_max * sizeof(int));

	if (ret_fds->flags & ~UNIX_FDS_ACCEPT_MASK)
		return ret_errno(EINVAL);

	if (hweight32((ret_fds->flags & ~UNIX_FDS_ACCEPT_NONE)) > 1)
		return ret_errno(EINVAL);

	if (ret_fds->fd_count_max >= KERNEL_SCM_MAX_FD)
		return ret_errno(EINVAL);

	if (ret_fds->fd_count_ret != 0)
		return ret_errno(EINVAL);

	cmsgbuf = zalloc(cmsgbufsize);
	if (!cmsgbuf)
		return ret_errno(ENOMEM);

	msg.msg_control		= cmsgbuf;
	msg.msg_controllen	= cmsgbufsize;

	msg.msg_iov	= ret_iov;
	msg.msg_iovlen	= size_ret_iov;

again:
	ret = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;

		return syserror("Failed to receive response");
	}
	if (ret == 0)
		return 0;

	/* If SO_PASSCRED is set we will always get a ucred message. */
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			__u32 idx;
			/*
			 * This causes some compilers to complain about
			 * increased alignment requirements but I haven't found
			 * a better way to deal with this yet. Suggestions
			 * welcome!
			 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			int *fds_raw = (int *)CMSG_DATA(cmsg);
#pragma GCC diagnostic pop
			__u32 num_raw = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

			/*
			 * We received an insane amount of file descriptors
			 * which exceeds the kernel limit we know about so
			 * close them and return an error.
			 */
			if (num_raw >= KERNEL_SCM_MAX_FD) {
				for (idx = 0; idx < num_raw; idx++)
					close(fds_raw[idx]);

				return syserror_set(-EFBIG, "Received excessive number of file descriptors");
			}

			if (msg.msg_flags & MSG_CTRUNC) {
				for (idx = 0; idx < num_raw; idx++)
					close(fds_raw[idx]);

				return syserror_set(-EFBIG, "Control message was truncated; closing all fds and rejecting incomplete message");
			}

			if (ret_fds->fd_count_max > num_raw) {
				if (!(ret_fds->flags & UNIX_FDS_ACCEPT_LESS)) {
					for (idx = 0; idx < num_raw; idx++)
						close(fds_raw[idx]);

					return syserror_set(-EINVAL, "Received fewer file descriptors than we expected %u != %u",
							    ret_fds->fd_count_max, num_raw);
				}

				/*
				 * Make sure any excess entries in the fd array
				 * are set to -EBADF so our cleanup functions
				 * can safely be called.
				 */
				for (idx = num_raw; idx < ret_fds->fd_count_max; idx++)
					ret_fds->fd[idx] = -EBADF;

				ret_fds->flags |= UNIX_FDS_RECEIVED_LESS;
			} else if (ret_fds->fd_count_max < num_raw) {
				if (!(ret_fds->flags & UNIX_FDS_ACCEPT_MORE)) {
					for (idx = 0; idx < num_raw; idx++)
						close(fds_raw[idx]);

					return syserror_set(-EINVAL, "Received more file descriptors than we expected %u != %u",
							    ret_fds->fd_count_max, num_raw);
				}

				/* Make sure we close any excess fds we received. */
				for (idx = ret_fds->fd_count_max; idx < num_raw; idx++)
					close(fds_raw[idx]);

				/* Cap the number of received file descriptors. */
				num_raw = ret_fds->fd_count_max;
				ret_fds->flags |= UNIX_FDS_RECEIVED_MORE;
			} else {
				ret_fds->flags |= UNIX_FDS_RECEIVED_EXACT;
			}

			if (hweight32((ret_fds->flags & ~UNIX_FDS_ACCEPT_MASK)) > 1) {
				for (idx = 0; idx < num_raw; idx++)
					close(fds_raw[idx]);

				return syserror_set(-EINVAL, "Invalid flag combination; closing to not risk leaking fds %u != %u",
						    ret_fds->fd_count_max, num_raw);
			}

			memcpy(ret_fds->fd, CMSG_DATA(cmsg), num_raw * sizeof(int));
			ret_fds->fd_count_ret = num_raw;
			break;
		}
	}

	if (ret_fds->fd_count_ret == 0) {
		ret_fds->flags |= UNIX_FDS_RECEIVED_NONE;

		/* We expected to receive file descriptors. */
		if ((ret_fds->flags & UNIX_FDS_ACCEPT_MASK) &&
		    !(ret_fds->flags & UNIX_FDS_ACCEPT_NONE))
			return syserror_set(-EINVAL, "Received no file descriptors");
	}

	return ret;
}

ssize_t lxc_abstract_unix_recv_fds(int fd, struct unix_fds *ret_fds,
				   void *ret_data, size_t size_ret_data)
{
	char buf[1] = {};
	struct iovec iov = {
		.iov_base	= ret_data ? ret_data : buf,
		.iov_len	= ret_data ? size_ret_data : sizeof(buf),
	};
	ssize_t ret;

	ret = lxc_abstract_unix_recv_fds_iov(fd, ret_fds, &iov, 1);
	if (ret < 0)
		return ret;

	return ret;
}

ssize_t lxc_abstract_unix_recv_one_fd(int fd, int *ret_fd, void *ret_data,
				      size_t size_ret_data)
{
	call_cleaner(put_unix_fds) struct unix_fds *fds = NULL;
	char buf[1] = {};
	struct iovec iov = {
		.iov_base	= ret_data ? ret_data : buf,
		.iov_len	= ret_data ? size_ret_data : sizeof(buf),
	};
	ssize_t ret;

	fds = &(struct unix_fds){
		.fd_count_max = 1,
	};

	ret = lxc_abstract_unix_recv_fds_iov(fd, fds, &iov, 1);
	if (ret < 0)
		return ret;

	if (ret == 0)
		return ret_errno(ENODATA);

	if (fds->fd_count_ret != fds->fd_count_max)
		*ret_fd = -EBADF;
	else
		*ret_fd = move_fd(fds->fd[0]);

	return ret;
}

ssize_t __lxc_abstract_unix_recv_two_fds(int fd, int *fd_first, int *fd_second,
					 void *data, size_t size)
{
	call_cleaner(put_unix_fds) struct unix_fds *fds = NULL;
	char buf[1] = {};
	struct iovec iov = {
	    .iov_base	= data ?: buf,
	    .iov_len	= size ?: sizeof(buf),
	};
	ssize_t ret;

	fds = &(struct unix_fds){
		.fd_count_max = 2,
	};

	ret = lxc_abstract_unix_recv_fds_iov(fd, fds, &iov, 1);
	if (ret < 0)
		return ret;

	if (ret == 0)
		return ret_errno(ENODATA);

	if (fds->fd_count_ret != fds->fd_count_max) {
		*fd_first = -EBADF;
		*fd_second = -EBADF;
	} else {
		*fd_first = move_fd(fds->fd[0]);
		*fd_second = move_fd(fds->fd[1]);
	}

	return 0;
}

int lxc_abstract_unix_send_credential(int fd, void *data, size_t size)
{
	struct msghdr msg = {0};
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct ucred cred = {
		.pid = lxc_raw_getpid(),
		.uid = getuid(),
		.gid = getgid(),
	};
	char cmsgbuf[CMSG_SPACE(sizeof(cred))] = {0};
	char buf[1] = {0};

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	memcpy(CMSG_DATA(cmsg), &cred, sizeof(cred));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = data ? data : buf;
	iov.iov_len = data ? size : sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return sendmsg(fd, &msg, MSG_NOSIGNAL);
}

int lxc_abstract_unix_rcv_credential(int fd, void *data, size_t size)
{
	struct msghdr msg = {0};
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct ucred cred;
	int ret;
	char cmsgbuf[CMSG_SPACE(sizeof(cred))] = {0};
	char buf[1] = {0};

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	iov.iov_base = data ? data : buf;
	iov.iov_len = data ? size : sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = recvmsg(fd, &msg, 0);
	if (ret <= 0)
		return ret;

	cmsg = CMSG_FIRSTHDR(&msg);

	if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
	    cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_CREDENTIALS) {
		memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));

		if (cred.uid && (cred.uid != getuid() || cred.gid != getgid()))
			return log_error_errno(-1, EACCES,
					       "Message denied for '%d/%d'",
					       cred.uid, cred.gid);
	}

	return ret;
}

int lxc_unix_sockaddr(struct sockaddr_un *ret, const char *path)
{
	size_t len;

	len = strlen(path);
	if (len == 0)
		return ret_set_errno(-1, EINVAL);
	if (path[0] != '/' && path[0] != '@')
		return ret_set_errno(-1, EINVAL);
	if (path[1] == '\0')
		return ret_set_errno(-1, EINVAL);

	if (len + 1 > sizeof(ret->sun_path))
		return ret_set_errno(-1, EINVAL);

	*ret = (struct sockaddr_un){
	    .sun_family = AF_UNIX,
	};

	if (path[0] == '@') {
		memcpy(ret->sun_path + 1, path + 1, len);
		return (int)(offsetof(struct sockaddr_un, sun_path) + len);
	}

	memcpy(ret->sun_path, path, len + 1);
	return (int)(offsetof(struct sockaddr_un, sun_path) + len + 1);
}

int lxc_unix_connect_type(struct sockaddr_un *addr, int type)
{
	__do_close int fd = -EBADF;
	int ret;
	ssize_t len;

	fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return log_error_errno(-1, errno,
				       "Failed to open new AF_UNIX socket");

	if (addr->sun_path[0] == '\0')
		len = strlen(&addr->sun_path[1]);
	else
		len = strlen(&addr->sun_path[0]);

	ret = connect(fd, (struct sockaddr *)addr,
		      offsetof(struct sockaddr_un, sun_path) + len);
	if (ret < 0)
		return log_error_errno(-1, errno,
				       "Failed to bind new AF_UNIX socket");

	return move_fd(fd);
}

int lxc_unix_connect(struct sockaddr_un *addr)
{
	return lxc_unix_connect_type(addr, SOCK_STREAM);
}

int lxc_socket_set_timeout(int fd, int rcv_timeout, int snd_timeout)
{
	struct timeval out = {0};
	int ret;

	out.tv_sec = snd_timeout;
	ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const void *)&out,
			 sizeof(out));
	if (ret < 0)
		return -1;

	out.tv_sec = rcv_timeout;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&out,
			 sizeof(out));
	if (ret < 0)
		return -1;

	return 0;
}
