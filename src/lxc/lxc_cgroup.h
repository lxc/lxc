/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef _cgroup_h
#define _cgroup_h

#define MAXPRIOLEN 24

#define CGROUP_CPU_SHARES "cpu.shares"
#define CGROUP_CPUACCT_USAGE "cpuacct.usage"
#define CGROUP_CPUSET_CPUS "cpuset.cpus"
#define CGROUP_CPUSET_CPU_EXCLUSIVE "cpuset.cpu_exclusive"
#define CGROUP_CPUSET_SCHED_LOAD_BALANCE "cpuset.sched_load_balance"
#define CGROUP_CPUSET_SCHED_RELAX_DOMAIN_LEVEL "cpuset.sched_relax_domain_level"
#define CGROUP_MEMORY_LIMIT_IN_BYTES "memory.limit_in_bytes"

struct lxc_cgroup_memory_info {
	unsigned long cache;
	unsigned long rss;
	unsigned long page_in;
	unsigned long page_out;
	unsigned long active;
	unsigned long inactive;
	unsigned long failcnt;
	unsigned long force_empty;
	unsigned long limit_in_bytes;
	unsigned long max_usage_in_bytes;
	unsigned long usage_in_bytes;
};

struct lxc_cgroup_cpuacct_info {
	unsigned long usage;
};

struct lxc_cgroup_cpu_info {
	unsigned long rt_period_us;
	unsigned long rt_runtimer_us;
	unsigned long shares;
};

struct lxc_cgroup_cpuset_info {
	int mem_exclusive;
	int mem_hardball;
	int memory_migrate;
	int memory_pressure;
	int memory_pressure_enabled;
	int memory_spread_page;
	int memory_spread_slab;
};

struct lxc_cgroup_info {
	struct lxc_cgroup_memory_info memory;
	struct lxc_cgroup_cpuacct_info cpuacct;
	struct lxc_cgroup_cpu_info cpu;
	struct lxc_cgroup_cpuset_info cpuset;
};

int lxc_get_cgroup_mount(const char *mtab, char *mnt);
int lxc_link_nsgroup(const char *name, pid_t pid);
int lxc_unlink_nsgroup(const char *name);
int lxc_cgroup_copy(const char *name, const char *subsystem);

#endif
