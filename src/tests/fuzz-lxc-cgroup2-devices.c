/*
 * SPDX-License-Identifier: LGPL-2.1+
 *
 * Fuzz the cgroup2 device rule pipeline (rule parsing + device filter
 * program construction) that lxc runs when a container configured with
 * "lxc.cgroup.devices.[allow|deny]" entries is started.
 *
 * Threat model: the container configuration file is untrusted input
 * (written by a less privileged user or shipped inside an untrusted
 * image/template). At container start cgfsng turns every
 * "devices.allow"/"devices.deny" value into a struct device_item via
 * device_cgroup_rule_parse() (or device_cgroup_rule_parse_devpath()
 * for absolute-path rules), accumulates the rules on
 * lxc_conf::bpf_devices with bpf_list_add_device() and finally builds
 * the device filter program with
 * bpf_program_{new,init,append_device,finalize}(). Bugs in this
 * pipeline either break container startup or install a wrong device
 * filter; the cgroup device filter is a security boundary, so parsing
 * and program construction must be robust against arbitrary rule
 * strings.
 *
 * The harness drives each fuzzed input line "<key> <value>" through
 * the real production parsers and the real device-list handling and
 * BPF program construction. It intentionally stops short of loading
 * or attaching the program (bpf_program_load_kernel()/
 * bpf_cgroup_devices_attach() require a writable cgroup hierarchy the
 * fuzzing sandbox does not provide). The two rule parsers are static
 * in cgfsng.c; fuzzing builds expose them through
 * FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION-guarded wrappers in
 * cgfsng.c.
 */

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cgroups/cgroup2_devices.h"
#include "conf.h"
#include "list.h"
#include "lxctest.h"
#include "macro.h"
#include "string_utils.h"

/* Fuzzing-only exposure of the static cgfsng.c rule parsers. */
extern int fuzz_lxc_device_cgroup_rule_parse(struct device_item *device,
					     const char *key, const char *val);
extern int fuzz_lxc_device_cgroup_rule_parse_devpath(struct device_item *device,
						     const char *val);

/* Bounds to keep a single input from dominating the fuzzing budget. */
#define MAX_RULES 128
#define MAX_RULE_LEN 512

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	__do_free char *buf = NULL;
	__do_bpf_program_free struct bpf_program *prog = NULL;
	struct lxc_conf *conf = NULL;
	char *line;
	int nrules = 0;

	/*
	 * 100Kb should probably be enough to trigger all the issues
	 * we're interested in without any timeouts
	 */
	if (size > 102400)
		return 0;

	conf = lxc_conf_init();
	lxc_test_assert_abort(conf);

	buf = (char *)malloc(size + 1);
	lxc_test_assert_abort(buf);
	memcpy(buf, data, size);
	buf[size] = '\0';

	lxc_iterate_parts(line, buf, "\r\n") {
		__attribute__((unused)) char *key, *val, *sp = NULL;
		struct device_item device = {};
		int ret;

		if (nrules++ > MAX_RULES)
			break;
		if (strlen(line) > MAX_RULE_LEN)
			continue;

		key = strtok_r(line, " \t", &sp);
		if (!key)
			continue;
		val = strtok_r(NULL, "", &sp);
		if (!val)
			continue;

		/* Mirror bpf_device_cgroup_prepare(). */
		if (strequal("devices.allow", key) && abspath(val))
			ret = fuzz_lxc_device_cgroup_rule_parse_devpath(&device, val);
		else
			ret = fuzz_lxc_device_cgroup_rule_parse(&device, key, val);
		if (ret < 0)
			continue;

		/* Note: both 0 and 1 are success, only negative fails. */
		ret = bpf_list_add_device(&conf->bpf_devices, &device);
		if (ret < 0)
			continue;
	}

	/* Build the device filter program the kernel would receive. */
	prog = bpf_program_new(BPF_CGROUP_DEVICE);
	lxc_test_assert_abort(prog);
	if (bpf_program_init(prog) == 0) {
		struct device_item *dev;

		list_for_each_entry(dev, &conf->bpf_devices.devices, head) {
			if (bpf_program_append_device(prog, dev) < 0)
				break;
		}
		bpf_program_finalize(prog);
	}

	lxc_conf_free(conf);

	return 0;
}
