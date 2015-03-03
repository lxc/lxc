#!/usr/bin/env lua
--
-- test the lxc lua api
--
-- Copyright © 2012 Oracle.
--
-- Authors:
-- Dwight Engen <dwight.engen@oracle.com>
--
-- This library is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License version 2, as
-- published by the Free Software Foundation.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
--

local lxc     = require("lxc")
local lfs     = require("lfs")
local getopt  = require("alt_getopt")

local LXC_PATH		= lxc.default_config_path_get()

local container
local cfg_containers	= {}
local optarg		= {}
local optind		= {}

function printf(...)
    local function wrapper(...) io.write(string.format(...)) end
    local status, result = pcall(wrapper, ...)
    if not status then
	error(result, 2)
    end
end

function log(level, ...)
    if (optarg["v"] >= level) then
	printf(os.date("%Y-%m-%d %T "))
	printf(...)
	printf("\n")
    end
end

function die(...)
    printf(...)
    os.exit(1)
end

function test_global_info()
    local cfg_containers
    local run_containers

    log(0, "%-20s %s", "LXC version:", lxc.version_get())
    log(0, "%-20s %s", "Container name:", optarg["n"])
    if (optarg["c"]) then
	log(0, "%-20s %s", "Creating container:", "yes")
	log(0, "%-20s %s", "With template:", optarg["t"])
    end
    log(0, "%-20s %s", "Containers path:", LXC_PATH)

    cfg_containers = lxc.containers_configured()
    log(0, "%-20s", "Containers configured:")
    for _,v in ipairs(cfg_containers) do
	log(0, "  %s", v)
    end

    run_containers = lxc.containers_running(true)
    log(0, "%-20s", "Containers running:")
    for _,v in ipairs(run_containers) do
	log(0, "  %s", v)
    end
end

function test_container_new()
    container = lxc.container:new(optarg["n"])
    assert(container ~= nil)
    assert(container:config_file_name() == string.format("%s/%s/config", LXC_PATH, optarg["n"]))
end

function test_container_config_path()
    local cfgcontainer
    local cfgpath = "/tmp/" .. optarg["n"]
    local cfgname = cfgpath .. "/config"

    log(0, "Test container config path...")

    -- create a config file in the new location from container's config
    assert(lfs.mkdir(cfgpath))
    assert(container:save_config(cfgname))
    cfgcontainer = lxc.container:new(optarg["n"], "/tmp")
    assert(cfgcontainer ~= nil)
    log(0, "cfgname:%s cfgpath:%s", cfgcontainer:config_file_name(), cfgcontainer:get_config_path())
    assert(cfgcontainer:config_file_name() == cfgname)
    assert(cfgcontainer:get_config_path() == "/tmp")
    assert(cfgcontainer:set_config_path(LXC_PATH))
    assert(cfgcontainer:get_config_path() == LXC_PATH)

    assert(os.remove(cfgname))
    assert(lfs.rmdir(cfgpath))
end

function test_container_create()
    if (optarg["c"]) then
	log(0, "%-20s %s", "Destroy existing container:", optarg["n"])
	container:destroy()
	assert(container:defined() == false)
    else
	local cfg_containers = lxc.containers_configured()
	if (cfg_containers[optarg["n"]]) then
	    log(0, "%-20s %s", "Use existing container:", optarg["n"])
	    return
	end
    end
    log(0, "%-20s %s", "Creating rootfs using:", optarg["t"])
    assert(container:create(optarg["t"]) == true)
    assert(container:defined() == true)
    assert(container:name() == optarg["n"])
end

function test_container_started()
    local now_running
    log(2, "state:%s pid:%d\n", container:state(), container:init_pid())
    assert(container:init_pid() > 1)
    assert(container:running() == true)
    assert(container:state() == "RUNNING")
    now_running = lxc.containers_running(true)
    assert(now_running[optarg["n"]] ~= nil)
    log(1, "%-20s %s", "Running, init pid:", container:init_pid())
end

function test_container_stopped()
    local now_running
    assert(container:init_pid() == -1)
    assert(container:running() == false)
    assert(container:state() == "STOPPED")
    now_running = lxc.containers_running(true)
    assert(now_running[optarg["n"]] == nil)
end

function test_container_frozen()
    local now_running
    assert(container:init_pid() > 1)
    assert(container:running() == true)
    assert(container:state() == "FROZEN")
    now_running = lxc.containers_running(true)
    assert(now_running[optarg["n"]] ~= nil)
end

function test_container_start()
    log(0, "Starting...")
    if (not container:start()) then
	log(1, "Start returned failure, waiting another 10 seconds...")
	container:wait("RUNNING", 10)
    end
    container:wait("RUNNING", 1)
end

function test_container_stop()
    log(0, "Stopping...")
    if (not container:stop()) then
	log(1, "Stop returned failure, waiting another 10 seconds...")
	container:wait("STOPPED", 10)
    end
    container:wait("STOPPED", 1)
end

function test_container_freeze()
    log(0, "Freezing...")
    if (not container:freeze()) then
	log(1, "Freeze returned failure, waiting another 10 seconds...")
	container:wait("FROZEN", 10)
    end
end

function test_container_unfreeze()
    log(0, "Unfreezing...")
    if (not container:unfreeze()) then
	log(1, "Unfreeze returned failure, waiting another 10 seconds...")
	container:wait("RUNNING", 10)
    end
end

function test_container_shutdown()
    log(0, "Shutting down...")
    container:shutdown(5)

    if (container:running()) then
	test_container_stop()
    end
end

function test_container_in_cfglist(should_find)
    local cfg_containers = lxc.containers_configured()

    if (should_find) then
	assert(cfg_containers[container:name()] ~= nil)
    else
	assert(cfg_containers[container:name()] == nil)
    end
end

function test_container_attach()
    log(0, "Test attach...")
    assert(container:running() == true)
    assert(container:attach("/bin/ps") == true)
end

function test_container_cgroup()
    log(0, "Test get/set cgroup items...")

    max_mem = container:get_cgroup_item("memory.max_usage_in_bytes")
    saved_limit = container:get_cgroup_item("memory.limit_in_bytes")
    assert(saved_limit ~= max_mem)
    assert(container:set_cgroup_item("memory.limit_in_bytes", max_mem))
    assert(container:get_cgroup_item("memory.limit_in_bytes") ~= saved_limit)
    assert(container:set_cgroup_item("memory.limit_in_bytes", "-1"))
end

function test_container_cmd()
    log(0, "Test get config from running container...")
    veth_pair = lxc.cmd_get_config_item(optarg["n"], "lxc.network.0.veth.pair")
    log(0, "  veth.pair:%s", veth_pair)
end

function test_config_items()
    log(0, "Test set/clear configuration items...")

    -- test setting a 'single type' item
    assert(container:get_config_item("lxc.utsname") == optarg["n"])
    container:set_config_item("lxc.utsname", "foobar")
    assert(container:get_config_item("lxc.utsname") == "foobar")
    container:set_config_item("lxc.utsname", optarg["n"])
    assert(container:get_config_item("lxc.utsname") == optarg["n"])

    -- test clearing/setting a 'list type' item
    container:clear_config_item("lxc.cap.drop")
    container:set_config_item("lxc.cap.drop", "new_cap1")
    container:set_config_item("lxc.cap.drop", "new_cap2")
    local cap_drop = container:get_config_item("lxc.cap.drop")
    assert(cap_drop["new_cap1"] ~= nil)
    assert(cap_drop["new_cap2"] ~= nil)
    -- note: clear_config_item only works on list type items
    container:clear_config_item("lxc.cap.drop")
    assert(container:get_config_item("lxc.cap.drop") == nil)

    local altname = "/tmp/" .. optarg["n"] .. ".altconfig"
    log(0, "Test saving to an alternate (%s) config file...", altname)
    assert(container:save_config(altname))
    assert(os.remove(altname))
end

function test_config_mount_entries()
    local mntents

    -- mount entries are a list type item
    mntents = container:get_config_item("lxc.mount.entry")
    log(0, "Mount entries:")
    for _,v in ipairs(mntents) do
	log(0, "  %s", v)
    end
end

function test_config_keys()
    local keys

    keys = container:get_keys()
    log(0, "Top level keys:")
    for k,v in pairs(keys) do
	log(0, "  %s = %s", k, v or "")
    end
end

function test_config_network(net_nr)
    log(0, "Test network %d config...", net_nr)
    local netcfg

    netcfg = container:get_keys("lxc.network." .. net_nr)
    if (netcfg == nil) then
	return
    end
    for k,v in pairs(netcfg) do
	log(0, "  %s = %s", k, v or "")
    end
    assert(netcfg["flags"] == "up")
    assert(container:get_config_item("lxc.network."..net_nr..".type") == "veth")
end


function usage()
    die("Usage: apitest <options>\n" ..
	"  -v|--verbose        increase verbosity with each -v\n" ..
	"  -h|--help           print help message\n" ..
	"  -n|--name           name of container to use for testing\n" ..
	"  -c|--create         create the test container anew\n" ..
	"  -l|--login          do interactive login test\n" ..
	"  -t|--template       template to use when creating test container\n"
    )
end

local long_opts = {
    verbose       = "v",
    help          = "h",
    name          = "n",
    create        = "c",
    template      = "t",
}

optarg,optind = alt_getopt.get_opts (arg, "hvn:ct:", long_opts)
optarg["v"] = tonumber(optarg["v"]) or 0
optarg["n"] = optarg["n"] or "lua-apitest"
optarg["c"] = optarg["c"] or nil
optarg["t"] = optarg["t"] or "busybox"
if (optarg["h"] ~= nil) then
    usage()
end

test_global_info()
test_container_new()
test_container_create()
test_container_stopped()
test_container_in_cfglist(true)
test_container_config_path()

test_config_items()
test_config_keys()
test_config_mount_entries()
test_config_network(0)

test_container_start()
test_container_started()

test_container_attach()
test_container_cgroup()
test_container_cmd()

test_container_freeze()
test_container_frozen()
test_container_unfreeze()
test_container_started()

test_container_shutdown()
test_container_stopped()
container:destroy()
test_container_in_cfglist(false)

log(0, "All tests passed")
