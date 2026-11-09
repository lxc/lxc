/*
 * SPDX-License-Identifier: LGPL-2.1+
 *
 * Fuzz the AF_UNIX plumbing of lxc's command/monitor protocol:
 *
 *  - lxc_abstract_unix_send_fds()/lxc_abstract_unix_recv_fds():
 *    the SCM_RIGHTS ancillary-data parser every lxc command reply
 *    and console/monitor fd handoff goes through,
 *  - lxc_abstract_unix_send_credential()/
 *    lxc_abstract_unix_rcv_credential(): the SCM_CREDENTIALS peer
 *    check used to authenticate command socket messages,
 *  - lxc_unix_sockaddr(): "lxc.monitor"-style socket address
 *    parsing, and
 *  - lxc_make_abstract_socket_name(): abstract socket name
 *    construction from container name + lxcpath (including the hash
 *    fallback for overlong names).
 *
 * Threat model: the peer on the other end of an lxc abstract unix
 * command/monitor socket is untrusted (a compromised container
 * process or a malicious local user can connect and craft messages
 * with arbitrary ancillary data). The receiver-side parsing in
 * af_unix.c must tolerate arbitrary fd counts, truncated control
 * messages and hostile flag combinations without leaking or
 * closing-wrong file descriptors. The address and name constructors
 * take configuration-controlled strings and must be robust against
 * overlong values.
 *
 * The harness drives a real socketpair through the production
 * send/receive functions with a flag matrix over UNIX_FDS_ACCEPT_*
 * and varying fd counts, plus the pure string parsers on fuzzed
 * strings. Input layout: byte 0 selects the matrix cell, followed by
 * two NUL-bounded strings (socket path, container name/lxcpath),
 * with the remainder used as SCM payload.
 */

#include "config.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "af_unix.h"
#include "commands_utils.h"
#include "lxctest.h"
#include "macro.h"
#include "memory_utils.h"
#include "utils.h"

#define FUZZ_MAX_STR 256
#define FUZZ_MAX_PAYLOAD 512

static const char *const fuzz_suffixes[] = { "command", "monitor", "state-client" };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct sockaddr_un addr = {};
	char sockname[sizeof(addr.sun_path)];
	uint8_t selector;
	const char *fpath, *fname;
	size_t pathlen, namelen, payload_len;
	const uint8_t *payload;
	int devnull = -EBADF;
	uint8_t dummy = '.';

	if (size < 4)
		return 0;
	if (size > 102400)
		return 0;

	selector = data[0];

	/* Two NUL-bounded strings followed by the raw SCM payload. All
	 * string lengths are bounded by the remaining input so that
	 * NUL-less inputs can never read past the buffer.
	 */
	fpath = (const char *)&data[1];
	pathlen = strnlen(fpath, size - 1);
	if (1 + pathlen + 1 >= size)
		return 0;
	fname = (const char *)&data[1 + pathlen + 1];
	namelen = strnlen(fname, size - (1 + pathlen + 1));
	if (1 + pathlen + 1 + namelen + 1 > size)
		return 0;
	payload = &data[1 + pathlen + 1 + namelen + 1];
	payload_len = size - (1 + pathlen + 1 + namelen + 1);
	if (payload_len > FUZZ_MAX_PAYLOAD)
		payload_len = FUZZ_MAX_PAYLOAD;

	/* Pure string parsing: socket address construction. */
	(void) lxc_unix_sockaddr(&addr, fpath);

	/* Pure string construction: abstract command socket names,
	 * including the hash fallback for overlong name/lxcpath
	 * combinations and small name buffers.
	 */
	if (selector & (1 << 0)) {
		char smallname[32];

		(void) lxc_make_abstract_socket_name(smallname, sizeof(smallname), fname, fpath, NULL,
						     fuzz_suffixes[selector % 3]);
	} else {
		(void) lxc_make_abstract_socket_name(sockname, sizeof(sockname), fname, fpath, NULL,
						     fuzz_suffixes[selector % 3]);
	}
	if (selector & (1 << 1))
		(void) lxc_make_abstract_socket_name(sockname, sizeof(sockname), fname, NULL, fname,
						     fuzz_suffixes[selector % 3]);

	/* SCM_RIGHTS send/receive matrix over a socketpair. */
	devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (devnull < 0)
		return 0;

	{
		__do_close int sv0 = -EBADF, sv1 = -EBADF;
		int fds[3];
		int sv[2];
		uint32_t want, flags;
		uint8_t nsend;
		uint8_t rbuf[FUZZ_MAX_PAYLOAD];

		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
			goto out;
		sv0 = sv[0];
		sv1 = sv[1];

		/*
		 * Safety net so a stray mismatch between sent and expected
		 * data can never block the fuzzer (production callers put
		 * timeouts on command sockets too).
		 */
		(void) lxc_socket_set_timeout(sv1, 1, 1);

		/* At most one of EXACT/LESS/MORE; NONE may be combined. */
		switch ((selector >> 2) & 0x3) {
		case 0:
			flags = UNIX_FDS_ACCEPT_EXACT;
			break;
		case 1:
			flags = UNIX_FDS_ACCEPT_LESS;
			break;
		case 2:
			flags = UNIX_FDS_ACCEPT_MORE;
			break;
		default:
			flags = UNIX_FDS_ACCEPT_LESS | UNIX_FDS_ACCEPT_NONE;
			break;
		}
		want = (selector >> 4) & 0x3;
		nsend = (selector >> 6) & 0x3;

		fds[0] = devnull;
		fds[1] = sv0;
		fds[2] = devnull;

		/*
		 * Always send at least one payload byte: production senders
		 * never send a bare cmsg, and an empty socket write would
		 * leave recvmsg() blocking forever.
		 */
		if (payload_len == 0) {
			payload = &dummy;
			payload_len = 1;
		}

		if (nsend > 0)
			(void) lxc_abstract_unix_send_fds(sv0, fds, nsend,
							  (void *)payload, payload_len);
		else
			(void) lxc_write_nointr(sv0, payload, payload_len);

		{
			struct unix_fds got = {
				.fd_count_max = want,
				.flags = flags,
			};

			(void) lxc_abstract_unix_recv_fds(sv1, &got, rbuf, sizeof(rbuf));
			put_unix_fds(&got);
		}

		/* SCM_CREDENTIALS authenticated ping-pong. */
		if (selector & (1 << 7)) {
			(void) lxc_abstract_unix_send_credential(sv0, (void *)payload, payload_len);
			(void) lxc_abstract_unix_rcv_credential(sv1, rbuf, sizeof(rbuf));
		}
	}

out:
	if (devnull >= 0)
		close(devnull);

	return 0;
}
