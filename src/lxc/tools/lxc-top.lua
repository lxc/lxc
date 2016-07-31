#!/usr/bin/env lua
--
-- top(1) like monitor for lxc containers
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

local lxc    = require("lxc")
local core   = require("lxc.core")
local getopt = require("alt_getopt")

local USER_HZ   = 100
local ESC       = string.format("%c", 27)
local TERMCLEAR = ESC.."[H"..ESC.."[J"
local TERMNORM  = ESC.."[0m"
local TERMBOLD  = ESC.."[1m"
local TERMRVRS  = ESC.."[7m"

local containers = {}
local stats = {}
local stats_total = {}
local max_containers

function printf(...)
    local function wrapper(...) io.write(string.format(...)) end
    local status, result = pcall(wrapper, ...)
    if not status then
	error(result, 2)
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

function strsisize(size, width)
    local KiB = 1024
    local MiB = 1048576
    local GiB = 1073741824
    local TiB = 1099511627776
    local PiB = 1125899906842624
    local EiB = 1152921504606846976
    local ZiB = 1180591620717411303424

    if (size >= ZiB) then
	return string.format("%d.%2.2d ZB", size / ZiB, (math.floor(size % ZiB) * 100) / ZiB)
    end
    if (size >= EiB) then
	return string.format("%d.%2.2d EB", size / EiB, (math.floor(size % EiB) * 100) / EiB)
    end
    if (size >= PiB) then
	return string.format("%d.%2.2d PB", size / PiB, (math.floor(size % PiB) * 100) / PiB)
    end
    if (size >= TiB) then
	return string.format("%d.%2.2d TB", size / TiB, (math.floor(size % TiB) * 100) / TiB)
    end
    if (size >= GiB) then
	return string.format("%d.%2.2d GB", size / GiB, (math.floor(size % GiB) * 100) / GiB)
    end
    if (size >= MiB) then
	return string.format("%d.%2.2d MB", size / MiB, (math.floor(size % MiB) * 1000) / (MiB * 10))
    end
    if (size >= KiB) then
	return string.format("%d.%2.2d KB", size / KiB, (math.floor(size % KiB) * 1000) / (KiB * 10))
    end
    return string.format("%3d.00   ", size)
end

function tty_lines()
    local rows = 25
    local f = assert(io.popen("stty -a | head -n 1"))
    for line in f:lines() do
	local stty_rows
	_,_,stty_rows = string.find(line, "rows (%d+)")
	if (stty_rows ~= nil) then
	    rows = stty_rows
	    break
	end
    end
    f:close()
    return rows
end

function container_sort(a, b)
    if (optarg["r"]) then
	if     (optarg["s"] == "n") then return (a > b)
	elseif (optarg["s"] == "c") then return (stats[a].cpu_use_nanos < stats[b].cpu_use_nanos)
	elseif (optarg["s"] == "d") then return (stats[a].blkio < stats[b].blkio)
	elseif (optarg["s"] == "m") then return (stats[a].mem_used < stats[b].mem_used)
	elseif (optarg["s"] == "k") then return (stats[a].kmem_used < stats[b].kmem_used)
	end
    else
	if     (optarg["s"] == "n") then return (a < b)
	elseif (optarg["s"] == "c") then return (stats[a].cpu_use_nanos > stats[b].cpu_use_nanos)
	elseif (optarg["s"] == "d") then return (stats[a].blkio > stats[b].blkio)
	elseif (optarg["s"] == "m") then return (stats[a].mem_used > stats[b].mem_used)
	elseif (optarg["s"] == "k") then return (stats[a].kmem_used > stats[b].kmem_used)
	end
    end
end

function container_list_update()
    local now_running

    now_running = lxc.containers_running(true)

    -- check for newly started containers
    for _,v in ipairs(now_running) do
	if (containers[v] == nil) then
	    local ct = lxc.container:new(v)
	    -- note, this is a "mixed" table, ie both dictionary and list
	    containers[v] = ct
	    table.insert(containers, v)
	end
    end

    -- check for newly stopped containers
    local indx = 1
    while (indx <= #containers) do
	local ctname = containers[indx]
	if (now_running[ctname] == nil) then
	    containers[ctname] = nil
	    stats[ctname] = nil
	    table.remove(containers, indx)
	else
	    indx = indx + 1
	end
    end

    -- get stats for all current containers and resort the list
    lxc.stats_clear(stats_total)
    for _,ctname in ipairs(containers) do
	stats[ctname] = containers[ctname]:stats_get(stats_total)
    end
    table.sort(containers, container_sort)
end

function stats_print_header(stats_total)
    printf(TERMRVRS .. TERMBOLD)
    printf("%-15s %8s %8s %8s %10s %10s", "Container", "CPU",  "CPU",  "CPU",  "BlkIO", "Mem")
    if (stats_total.kmem_used > 0) then printf(" %10s", "KMem") end
    printf("\n")

    printf("%-15s %8s %8s %8s %10s %10s", "Name",      "Used", "Sys",  "User", "Total", "Used")
    if (stats_total.kmem_used > 0) then printf(" %10s", "Used") end
    printf("\n")
    printf(TERMNORM)
end

function stats_print(name, stats, stats_total)
    printf("%-15s %8.2f %8.2f %8.2f %10s %10s",
	   name,
	   stats.cpu_use_nanos / 1000000000,
	   stats.cpu_use_sys  / USER_HZ,
	   stats.cpu_use_user / USER_HZ,
	   strsisize(stats.blkio),
	   strsisize(stats.mem_used))
    if (stats_total.kmem_used > 0) then
	printf(" %10s", strsisize(stats.kmem_used))
    end
end

function usage()
    printf("Usage: lxc-top [options]\n" ..
	"  -h|--help      print this help message\n" ..
	"  -m|--max       display maximum number of containers\n" ..
	"  -d|--delay     delay in seconds between refreshes (default: 3.0)\n" ..
	"  -s|--sort      sort by [n,c,d,m] (default: n) where\n" ..
	"                 n = Name\n" ..
	"                 c = CPU use\n" ..
	"                 d = Disk I/O use\n" ..
	"                 m = Memory use\n" ..
	"                 k = Kernel memory use\n" ..
	"  -r|--reverse   sort in reverse (descending) order\n"
    )
    os.exit(1)
end

local long_opts = {
    help      = "h",
    delay     = "d",
    max       = "m",
    reverse   = "r",
    sort      = "s",
}

optarg,optind = alt_getopt.get_opts (arg, "hd:m:rs:", long_opts)
optarg["d"] = tonumber(optarg["d"]) or 3.0
optarg["m"] = tonumber(optarg["m"]) or tonumber(tty_lines() - 3)
optarg["r"] = optarg["r"] or false
optarg["s"] = optarg["s"] or "n"
if (optarg["h"] ~= nil) then
    usage()
end

while true
do
    container_list_update()
    -- if some terminal we care about doesn't support the simple escapes, we
    -- may fall back to this, or ncurses. ug.
    --os.execute("tput clear")
    printf(TERMCLEAR)
    stats_print_header(stats_total)
    for index,ctname in ipairs(containers) do
	stats_print(ctname, stats[ctname], stats_total)
	printf("\n")
	if (index >= optarg["m"]) then
	    break
	end
    end
    stats_print(string.format("TOTAL (%-2d)", #containers), stats_total, stats_total)
    io.flush()
    core.usleep(optarg["d"] * 1000000)
end
