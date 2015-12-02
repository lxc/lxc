--
-- lua lxc module
--
-- Copyright © 2012 Oracle.
--
-- Authors:
-- Dwight Engen <dwight.engen@oracle.com>
--
--  This library is free software; you can redistribute it and/or
--  modify it under the terms of the GNU Lesser General Public
--  License as published by the Free Software Foundation; either
--  version 2.1 of the License, or (at your option) any later version.
--
--  This library is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
--  Lesser General Public License for more details.
--
--  You should have received a copy of the GNU Lesser General Public
--  License along with this library; if not, write to the Free Software
--  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
--

local core   = require("lxc.core")
local lfs    = require("lfs")
local table  = require("table")
local string = require("string")
local io     = require("io")
module("lxc", package.seeall)

local lxc_path
local log_level = 3

-- lua 5.1 compat
if table.unpack == nil then
    table.unpack = unpack
end

-- the following two functions can be useful for debugging
function printf(...)
    local function wrapper(...) io.write(string.format(...)) end
    local status, result = pcall(wrapper, ...)
    if not status then
	error(result, 2)
    end
end

function log(level, ...)
    if (log_level >= level) then
	printf(os.date("%Y-%m-%d %T "))
	printf(...)
    end
end

function string:split(delim, max_cols)
    local cols = {}
    local start = 1
    local nextc
    repeat
	nextc = string.find(self, delim, start)
	if (nextc and #cols ~= max_cols - 1) then
	    table.insert(cols, string.sub(self, start, nextc-1))
	    start = nextc + #delim
	else
	    table.insert(cols, string.sub(self, start, string.len(self)))
	    nextc = nil
	end
    until nextc == nil or start > #self
    return cols
end

-- container class
container = {}
container_mt = {}
container_mt.__index = container

function container:new(lname, config)
    local lcore
    local lnetcfg = {}
    local lstats = {}

    if lname then
	if config then
	    lcore = core.container_new(lname, config)
	else
	    lcore = core.container_new(lname)
	end
    end

    return setmetatable({ctname = lname, core = lcore, netcfg = lnetcfg, stats = lstats}, container_mt)
end

-- methods interfacing to core functionality
function container:attach(what, ...)
    return self.core:attach(what, ...)
end

function container:config_file_name()
    return self.core:config_file_name()
end

function container:defined()
    return self.core:defined()
end

function container:init_pid()
    return self.core:init_pid()
end

function container:name()
    return self.core:name()
end

function container:start()
    return self.core:start()
end

function container:stop()
    return self.core:stop()
end

function container:shutdown(timeout)
    return self.core:shutdown(timeout)
end

function container:wait(state, timeout)
    return self.core:wait(state, timeout)
end

function container:freeze()
    return self.core:freeze()
end

function container:unfreeze()
    return self.core:unfreeze()
end

function container:running()
    return self.core:running()
end

function container:state()
    return self.core:state()
end

function container:create(template, ...)
    return self.core:create(template, ...)
end

function container:destroy()
    return self.core:destroy()
end

-- return nil if name missing
function container:rename(name)
    return self.core:rename(name)
end

function container:get_config_path()
    return self.core:get_config_path()
end

function container:set_config_path(path)
    return self.core:set_config_path(path)
end

function container:append_config_item(key, value)
    return self.core:set_config_item(key, value)
end

function container:clear_config_item(key)
    return self.core:clear_config_item(key)
end

function container:get_cgroup_item(key)
    return self.core:get_cgroup_item(key)
end

function container:get_config_item(key)
    local value
    local vals = {}

    value = self.core:get_config_item(key)

    -- check if it is a single item
    if (not value or not string.find(value, "\n")) then
	return value
    end

    -- it must be a list type item, make a table of it
    vals = value:split("\n", 1000)
    -- make it a "mixed" table, ie both dictionary and list for ease of use
    for _,v in ipairs(vals) do
	vals[v] = true
    end
    return vals
end

function container:set_cgroup_item(key, value)
    return self.core:set_cgroup_item(key, value)
end

function container:set_config_item(key, value)
    return self.core:set_config_item(key, value)
end

function container:get_keys(base)
    local ktab = {}
    local keys

    if (base) then
	keys = self.core:get_keys(base)
	base = base .. "."
    else
	keys = self.core:get_keys()
	base = ""
    end
    if (keys == nil) then
	return nil
    end
    keys = keys:split("\n", 1000)
    for _,v in ipairs(keys) do
	local config_item = base .. v
	ktab[v] = self.core:get_config_item(config_item)
    end
    return ktab
end

-- return nil or more args
function container:get_interfaces()
    return self.core:get_interfaces()
end

-- return nil or more args
function container:get_ips(...)
    return self.core:get_ips(...)
end

function container:load_config(alt_path)
    if (alt_path) then
	return self.core:load_config(alt_path)
    else
	return self.core:load_config()
    end
end

function container:save_config(alt_path)
    if (alt_path) then
	return self.core:save_config(alt_path)
    else
	return self.core:save_config()
    end
end

-- methods for stats collection from various cgroup files
-- read integers at given coordinates from a cgroup file
function container:stat_get_ints(item, coords)
    local lines = {}
    local result = {}
    local flines = self:get_cgroup_item(item)

    if (flines == nil) then
	for k,c in ipairs(coords) do
	    table.insert(result, 0)
	end
    else
	for line in flines:gmatch("[^\r\n]+") do
	    table.insert(lines, line)
	end
	for k,c in ipairs(coords) do
	    local col

	    col = lines[c[1]]:split(" ", 80)
	    local val = tonumber(col[c[2]])
	    table.insert(result, val)
	end
    end
    return table.unpack(result)
end

-- read an integer from a cgroup file
function container:stat_get_int(item)
    local line = self:get_cgroup_item(item)
    -- if line is nil (on an error like Operation not supported because
    -- CONFIG_MEMCG_SWAP_ENABLED isn't enabled) return 0
    return tonumber(line) or 0
end

function container:stat_match_get_int(item, match, column)
    local val
    local lines = self:get_cgroup_item(item)

    if (lines == nil) then
       return 0
    end

    for line in lines:gmatch("[^\r\n]+") do
	if (string.find(line, match)) then
	    local col

	    col = line:split(" ", 80)
	    val = tonumber(col[column]) or 0
	end
    end

    return val
end

function container:stats_get(total)
    local stat = {}
    stat.mem_used      = self:stat_get_int("memory.usage_in_bytes")
    stat.mem_limit     = self:stat_get_int("memory.limit_in_bytes")
    stat.memsw_used    = self:stat_get_int("memory.memsw.usage_in_bytes")
    stat.memsw_limit   = self:stat_get_int("memory.memsw.limit_in_bytes")
    stat.kmem_used     = self:stat_get_int("memory.kmem.usage_in_bytes")
    stat.kmem_limit    = self:stat_get_int("memory.kmem.limit_in_bytes")
    stat.cpu_use_nanos = self:stat_get_int("cpuacct.usage")
    stat.cpu_use_user,
    stat.cpu_use_sys   = self:stat_get_ints("cpuacct.stat", {{1, 2}, {2, 2}})
    stat.blkio         = self:stat_match_get_int("blkio.throttle.io_service_bytes", "Total", 2)

    if (total) then
	total.mem_used      = total.mem_used      + stat.mem_used
	total.mem_limit     = total.mem_limit     + stat.mem_limit
	total.memsw_used    = total.memsw_used    + stat.memsw_used
	total.memsw_limit   = total.memsw_limit   + stat.memsw_limit
	total.kmem_used     = total.kmem_used     + stat.kmem_used
	total.kmem_limit    = total.kmem_limit    + stat.kmem_limit
	total.cpu_use_nanos = total.cpu_use_nanos + stat.cpu_use_nanos
	total.cpu_use_user  = total.cpu_use_user  + stat.cpu_use_user
	total.cpu_use_sys   = total.cpu_use_sys   + stat.cpu_use_sys
	total.blkio         = total.blkio         + stat.blkio
    end
    return stat
end

local M = { container = container }

function M.stats_clear(stat)
    stat.mem_used      = 0
    stat.mem_limit     = 0
    stat.memsw_used    = 0
    stat.memsw_limit   = 0
    stat.kmem_used     = 0
    stat.kmem_limit    = 0
    stat.cpu_use_nanos = 0
    stat.cpu_use_user  = 0
    stat.cpu_use_sys   = 0
    stat.blkio         = 0
end

-- return configured containers found in LXC_PATH directory
function M.containers_configured(names_only)
    local containers = {}

    for dir in lfs.dir(lxc_path) do
	if (dir ~= "." and dir ~= "..")
	then
	    local cfgfile = lxc_path .. "/" .. dir .. "/config"
	    local cfgattr = lfs.attributes(cfgfile)

	    if (cfgattr and cfgattr.mode == "file") then
		if (names_only) then
		    -- note, this is a "mixed" table, ie both dictionary and list
		    containers[dir] = true
		    table.insert(containers, dir)
		else
		    local ct = container:new(dir)
		    -- note, this is a "mixed" table, ie both dictionary and list
		    containers[dir] = ct
		    table.insert(containers, dir)
		end
	    end
	end
    end
    table.sort(containers, function (a,b) return (a < b) end)
    return containers
end

-- return running containers found in cgroup fs
function M.containers_running(names_only)
    local containers = {}
    local names = M.containers_configured(true)

    for _,name in ipairs(names) do
	local ct = container:new(name)
	if ct:running() then
		-- note, this is a "mixed" table, ie both dictionary and list
		table.insert(containers, name)
		if (names_only) then
		    containers[name] = true
		    ct = nil
		else
		    containers[name] = ct
		end
	end
    end

    table.sort(containers, function (a,b) return (a < b) end)
    return containers
end

function M.version_get()
    return core.version_get()
end

function M.default_config_path_get()
    return core.default_config_path_get()
end

function M.cmd_get_config_item(name, item, lxcpath)
    if (lxcpath) then
	return core.cmd_get_config_item(name, item, lxcpath)
    else
	return core.cmd_get_config_item(name, item)
    end
end

lxc_path = core.default_config_path_get()

return M
