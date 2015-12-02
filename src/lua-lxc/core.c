/*
 * lua-lxc: lua bindings for lxc
 *
 * Copyright © 2012 Oracle.
 *
 * Authors:
 * Dwight Engen <dwight.engen@oracle.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.

 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.

 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define LUA_LIB
#define _GNU_SOURCE
#include <lua.h>
#include <lauxlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <lxc/lxccontainer.h>
#include "lxc/commands.h"

#if LUA_VERSION_NUM < 502
#define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#define luaL_setfuncs(L,l,n) (assert(n==0), luaL_register(L,NULL,l))
#define luaL_checkunsigned(L,n) luaL_checknumber(L,n)
#endif

#if LUA_VERSION_NUM >= 503
#ifndef luaL_checkunsigned
#define luaL_checkunsigned(L,n) ((lua_Unsigned)luaL_checkinteger(L,n))
#endif
#endif

#ifdef NO_CHECK_UDATA
#define checkudata(L,i,tname)	lua_touserdata(L, i)
#else
#define checkudata(L,i,tname)	luaL_checkudata(L, i, tname)
#endif

#define lua_boxpointer(L,u) \
    (*(void **) (lua_newuserdata(L, sizeof(void *))) = (u))

#define lua_unboxpointer(L,i,tname) \
    (*(void **) (checkudata(L, i, tname)))

#define CONTAINER_TYPENAME	"lxc.container"

/* Max Lua arguments for function */
#define MAXVARS	200

static int container_new(lua_State *L)
{
    struct lxc_container *c;
    const char *name = luaL_checkstring(L, 1);
    const char *configpath = NULL;
    int argc = lua_gettop(L);

    if (argc > 1)
	configpath = luaL_checkstring(L, 2);

    c = lxc_container_new(name, configpath);
    if (c) {
	lua_boxpointer(L, c);
	luaL_getmetatable(L, CONTAINER_TYPENAME);
	lua_setmetatable(L, -2);
    } else {
	lua_pushnil(L);
    }
    return 1;
}

static int container_gc(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    /* XXX what to do if this fails? */
    lxc_container_put(c);
    return 0;
}

static int container_config_file_name(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    char *config_file_name;

    config_file_name = c->config_file_name(c);
    lua_pushstring(L, config_file_name);
    free(config_file_name);
    return 1;
}

static int container_defined(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    lua_pushboolean(L, !!c->is_defined(c));
    return 1;
}

static int container_name(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    lua_pushstring(L, c->name);
    return 1;
}

static int container_create(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    char *template_name = strdupa(luaL_checkstring(L, 2));
    int argc = lua_gettop(L);
    char **argv;
    int i;

    argv = alloca((argc+1) * sizeof(char *));
    for (i = 0; i < argc-2; i++)
	argv[i] = strdupa(luaL_checkstring(L, i+3));
    argv[i] = NULL;

    lua_pushboolean(L, !!c->create(c, template_name, NULL, NULL, 0, argv));
    return 1;
}

static int container_destroy(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    lua_pushboolean(L, !!c->destroy(c));
    return 1;
}

/* container state */
static int container_start(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    int argc = lua_gettop(L);
    char **argv = NULL;
    int i,j;
    int useinit = 0;

    if (argc > 1) {
	argv = alloca((argc+1) * sizeof(char *));
	for (i = 0, j = 0; i < argc-1; i++) {
	    const char *arg = luaL_checkstring(L, i+2);

	    if (!strcmp(arg, "useinit"))
		useinit = 1;
	    else
		argv[j++] = strdupa(arg);
	}
	argv[j] = NULL;
    }

    c->want_daemonize(c, true);
    lua_pushboolean(L, !!c->start(c, useinit, argv));
    return 1;
}

static int container_stop(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    lua_pushboolean(L, !!c->stop(c));
    return 1;
}

static int container_shutdown(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    int timeout = luaL_checkinteger(L, 2);

    lua_pushboolean(L, !!c->shutdown(c, timeout));
    return 1;
}

static int container_wait(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *state = luaL_checkstring(L, 2);
    int timeout = luaL_checkinteger(L, 3);

    lua_pushboolean(L, !!c->wait(c, state, timeout));
    return 1;
}

static int container_rename(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *new_name;
    int argc = lua_gettop(L);

    if (argc > 1) {
	new_name = luaL_checkstring(L, 2);
	lua_pushboolean(L, !!c->rename(c, new_name));
    } else
	lua_pushnil(L);
    return 1;
}

static int container_freeze(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    lua_pushboolean(L, !!c->freeze(c));
    return 1;
}

static int container_unfreeze(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    lua_pushboolean(L, !!c->unfreeze(c));
    return 1;
}

static int container_running(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    lua_pushboolean(L, !!c->is_running(c));
    return 1;
}

static int container_state(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    lua_pushstring(L, c->state(c));
    return 1;
}

static int container_init_pid(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);

    lua_pushinteger(L, c->init_pid(c));
    return 1;
}

/* configuration file methods */
static int container_load_config(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    int arg_cnt = lua_gettop(L);
    const char *alt_path = NULL;

    if (arg_cnt > 1)
	alt_path = luaL_checkstring(L, 2);

    lua_pushboolean(L, !!c->load_config(c, alt_path));
    return 1;
}

static int container_save_config(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    int arg_cnt = lua_gettop(L);
    const char *alt_path = NULL;

    if (arg_cnt > 1)
	alt_path = luaL_checkstring(L, 2);

    lua_pushboolean(L, !!c->save_config(c, alt_path));
    return 1;
}

static int container_get_config_path(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *config_path;

    config_path = c->get_config_path(c);
    lua_pushstring(L, config_path);
    return 1;
}

static int container_set_config_path(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *config_path = luaL_checkstring(L, 2);

    lua_pushboolean(L, !!c->set_config_path(c, config_path));
    return 1;
}

static int container_clear_config_item(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *key = luaL_checkstring(L, 2);

    lua_pushboolean(L, !!c->clear_config_item(c, key));
    return 1;
}

static int container_get_cgroup_item(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *key = luaL_checkstring(L, 2);
    int len;
    char *value;

    len = c->get_cgroup_item(c, key, NULL, 0);
    if (len <= 0)
	goto not_found;

    value = alloca(sizeof(char)*len + 1);
    if (c->get_cgroup_item(c, key, value, len + 1) != len)
	goto not_found;

    lua_pushstring(L, value);
    return 1;

not_found:
    lua_pushnil(L);
    return 1;
}

static int container_get_config_item(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *key = luaL_checkstring(L, 2);
    int len;
    char *value;

    len = c->get_config_item(c, key, NULL, 0);
    if (len <= 0)
	goto not_found;

    value = alloca(sizeof(char)*len + 1);
    if (c->get_config_item(c, key, value, len + 1) != len)
	goto not_found;

    lua_pushstring(L, value);
    return 1;

not_found:
    lua_pushnil(L);
    return 1;
}

static int container_set_cgroup_item(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *key = luaL_checkstring(L, 2);
    const char *value = luaL_checkstring(L, 3);

    lua_pushboolean(L, !!c->set_cgroup_item(c, key, value));
    return 1;
}

static int container_set_config_item(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *key = luaL_checkstring(L, 2);
    const char *value = luaL_checkstring(L, 3);

    lua_pushboolean(L, !!c->set_config_item(c, key, value));
    return 1;
}

static int container_get_keys(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    const char *key = NULL;
    int len;
    char *value;
    int arg_cnt = lua_gettop(L);

    if (arg_cnt > 1)
	key = luaL_checkstring(L, 2);

    len = c->get_keys(c, key, NULL, 0);
    if (len <= 0)
	goto not_found;

    value = alloca(sizeof(char)*len + 1);
    if (c->get_keys(c, key, value, len + 1) != len)
	goto not_found;

    lua_pushstring(L, value);
    return 1;

not_found:
    lua_pushnil(L);
    return 1;
}

static int container_attach(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    int argc = lua_gettop(L);
    char **argv = NULL;
    int i;

    if (argc > 1) {
	argv = alloca((argc+1) * sizeof(char *));
	for (i = 0; i < argc-1; i++) {
		const char *arg = luaL_checkstring(L, i+2);
		argv[i] = strdupa(arg);
	}
	argv[i] = NULL;
    }
    else
    {
    	lua_pushnil(L);
    	return 1;
    }

    lua_pushboolean(L, !(c->attach_run_wait(c, NULL, argv[0], (const char**)argv)));
    return 1;
}

static int container_get_interfaces(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    char **ifaces;
    int i;

    ifaces = c->get_interfaces(c);

    if (!ifaces){
	lua_pushnil(L);
	return 1;
    }

    for (i = 0; ifaces[i]; i++);

    /* protect LUA stack form overflow */
    if (i > MAXVARS || !lua_checkstack(L, i)){
        for (i = 0; ifaces[i]; i++)
	    free(ifaces[i]);
	lua_pushnil(L);
	return 1;
    }
    for (i = 0; ifaces[i]; i++){
	lua_pushstring(L, ifaces[i]);
	free(ifaces[i]);
    }
    return i;
}

static int container_get_ips(lua_State *L)
{
    struct lxc_container *c = lua_unboxpointer(L, 1, CONTAINER_TYPENAME);
    int argc = lua_gettop(L);
    char **addresses;
    char *iface = NULL, *family = NULL;
    int i, scope = 0;

    if (argc > 1)
	iface = (char *)luaL_checkstring(L, 2);
    if (argc > 2)
	family = (char *)luaL_checkstring(L, 3);
    if (argc > 3)
	scope = luaL_checkinteger(L, 4);

    addresses = c->get_ips(c, iface, family, scope);

    if (!addresses){
	lua_pushnil(L);
	return 1;
    }

    for (i = 0; addresses[i]; i++);

    /* protect LUA stack form overflow */
    if (i > MAXVARS || !lua_checkstack(L, i)){
        for (i = 0; addresses[i]; i++)
	    free(addresses[i]);
	lua_pushnil(L);
	return 1;
    }
    for (i = 0; addresses[i]; i++){
	lua_pushstring(L, addresses[i]);
	free(addresses[i]);
    }
    return i;
}

static luaL_Reg lxc_container_methods[] =
{
    {"attach",                  container_attach},
    {"create",			container_create},
    {"defined",			container_defined},
    {"destroy",			container_destroy},
    {"init_pid",		container_init_pid},
    {"name",			container_name},
    {"running",			container_running},
    {"state",			container_state},
    {"freeze",			container_freeze},
    {"unfreeze",		container_unfreeze},
    {"start",			container_start},
    {"stop",			container_stop},
    {"shutdown",		container_shutdown},
    {"wait",			container_wait},
    {"rename",			container_rename},

    {"config_file_name",	container_config_file_name},
    {"load_config",		container_load_config},
    {"save_config",		container_save_config},
    {"get_cgroup_item",		container_get_cgroup_item},
    {"set_cgroup_item",		container_set_cgroup_item},
    {"get_config_path",		container_get_config_path},
    {"set_config_path",		container_set_config_path},
    {"get_config_item",		container_get_config_item},
    {"set_config_item",		container_set_config_item},
    {"clear_config_item",	container_clear_config_item},
    {"get_keys",		container_get_keys},
    {"get_interfaces",		container_get_interfaces},
    {"get_ips",			container_get_ips},
    {NULL, NULL}
};

static int lxc_version_get(lua_State *L) {
    lua_pushstring(L, VERSION);
    return 1;
}

static int lxc_default_config_path_get(lua_State *L) {
    const char *lxcpath = lxc_get_global_config_item("lxc.lxcpath");

    lua_pushstring(L, lxcpath);
    return 1;
}

static int cmd_get_config_item(lua_State *L)
{
    int arg_cnt = lua_gettop(L);
    const char *name = luaL_checkstring(L, 1);
    const char *key = luaL_checkstring(L, 2);
    const char *lxcpath = NULL;
    char *value;

    if (arg_cnt > 2)
	lxcpath = luaL_checkstring(L, 3);

    value = lxc_cmd_get_config_item(name, key, lxcpath);
    if (!value)
	goto not_found;

    lua_pushstring(L, value);
    return 1;

not_found:
    lua_pushnil(L);
    return 1;
}

/* utility functions */
static int lxc_util_usleep(lua_State *L) {
    usleep((useconds_t)luaL_checkunsigned(L, 1));
    return 0;
}

static int lxc_util_dirname(lua_State *L) {
    char *path = strdupa(luaL_checkstring(L, 1));
    lua_pushstring(L, dirname(path));
    return 1;
}

static luaL_Reg lxc_lib_methods[] = {
    {"version_get",		lxc_version_get},
    {"default_config_path_get",	lxc_default_config_path_get},
    {"cmd_get_config_item",	cmd_get_config_item},
    {"container_new",		container_new},
    {"usleep",			lxc_util_usleep},
    {"dirname",			lxc_util_dirname},
    {NULL, NULL}
};

static int lxc_lib_uninit(lua_State *L) {
    (void) L;
    /* this is where we would fini liblxc.so if we needed to */
    return 0;
}

LUALIB_API int luaopen_lxc_core(lua_State *L) {
    /* this is where we would initialize liblxc.so if we needed to */

    luaL_newlib(L, lxc_lib_methods);

    lua_newuserdata(L, 0);
    lua_newtable(L);  /* metatable */
    lua_pushvalue(L, -1);
    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, lxc_lib_uninit);
    lua_rawset(L, -3);
    lua_setmetatable(L, -3);
    lua_rawset(L, -3);

    luaL_newmetatable(L, CONTAINER_TYPENAME);
    luaL_setfuncs(L, lxc_container_methods, 0);
    lua_pushvalue(L, -1);  /* push metatable */
    lua_pushstring(L, "__gc");
    lua_pushcfunction(L, container_gc);
    lua_settable(L, -3);
    lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
    lua_pop(L, 1);
    return 1;
}
