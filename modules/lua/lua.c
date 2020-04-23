/*
 * Copyright (C) 2006-2020  Andrej N. Gritsenko <andrej@rep.kiev.ua>
 *
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * The FoxEye "lua" module: script interpreter for Lua programming language.
 */

#include "foxeye.h"
#include "modules.h"

#ifdef HAVE_LIBLUA
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#ifndef HAVE_LIBLUA51
# define luaL_Reg luaL_reg
# define luaL_register(a,b,c) luaL_openlib (a,b,c,0)
# define lua_pushinteger lua_pushnumber
# define luaL_openlibs lua_baselibopen
# define luaL_newstate lua_open
#endif

#ifndef LUA_VERSION_NUM
# define LUA_VERSION_NUM 500
#endif

#if LUA_VERSION_NUM > 501
# define lua_equal(L,idx1,idx2) lua_compare(L,(idx1),(idx2),LUA_OPEQ)
#endif

#if LUA_VERSION_NUM > 502
# define luaL_checklong luaL_checkinteger
#endif

#include "init.h"
#include "tree.h"
#include "direct.h"
#include "wtmp.h"
#include "sheduler.h"

static lua_State *Lua = NULL;

static long int _lua_max_timer = 172800;

#define _lua_getfoxeye(l) lua_getglobal(l, "foxeye"); /* T */ \
			  if (!lua_istable(l, -1)) return 0

static inline int _lua_getbindtableslist (lua_State *L) /* -> BB */
{
  _lua_getfoxeye (L); /* T */
  lua_pushstring (L, "__binds"); /* T b */
  lua_rawget (L, -2); /* T BB */
  lua_remove (L, -2); /* BB */
  if (!lua_istable (L, -1))
    return 0;
  return 1;
}

static inline int _lua_getbindlist (lua_State *L, const char *bt) /* -> B */
{
  dprint (5, "lua:_lua_getbindlist on %s.", bt);
  if (!_lua_getbindtableslist (L))
    return 0;
  lua_pushstring (L, bt); /* BB n */
  lua_rawget (L, -2); /* BB B */
  if (!lua_istable (L, -1))
  {
    lua_pop (L, 1); /* BB */
    lua_newtable (L); /* BB B */
    lua_pushstring (L, bt); /* BB B n */
    lua_pushvalue (L, -2); /* BB B n B */
    lua_settable (L, -4); /* BB B */
  }
  lua_remove (L, -2); /* B */
  return 1;
}

static inline void _lua_clearbindlist (lua_State *L, int t) /* -> */
{
  if (_lua_getbindtableslist (L)) /* BB */
  {
    lua_pushvalue (L, t); /* BB t */
    lua_pushnil (L); /* BB t nil */
    lua_settable (L, -3); /* BB */
  }
  lua_pop (L, 1); /* */
}

static int _lua_scanbindlists (lua_State *L, int t) /* -> */
{
  int n;

  if (!_lua_getbindtableslist (L)) /* BB */
  {
    lua_pop (L, 1);
    return -1;
  }
  n = 0;
  lua_pushstring (L, "*"); /* BB a */
  lua_rawget (L, -2); /* BB A */
  lua_pushnil (L); /* BB A nil */
  while (lua_next (L, -3)) /* BB A k B */
  {
    if (lua_istable (L, -1) && !lua_equal (L, -1, -3))
    {
      lua_pushvalue (L, t); /* BB A k B n */
      lua_rawget (L, -2); /* BB A k B f */
      if (!lua_isnil (L, -1))
	n++;
      lua_pop (L, 1); /* BB A k B */
    }
    lua_pop (L, 1); /* BB A k */
  } /* BB A */
  lua_pop (L, 2); /* */
  return n;
}

static inline int _lua_getbinding (lua_State *L, int n, const char *name) /* -> n f */
{
  dprint (5, "lua:_lua_getbinding on %s.", name);
  lua_pushstring (L, name); /* n */
  lua_pushvalue (L, -1); /* n n */
  lua_gettable (L, n); /* n f */
  if (!lua_isfunction (L, -1))
    return 0;
  return 1;
}

/*
 * Calls from FoxEye to Lua (bindings)
 */
static int binding_lua (char *name, int argc, const char *argv[])
{
  int i = 0;

  dprint (5, "lua:binding_lua call for %s.", name);
  if (!safe_strcmp (name, "-"))
  {
    BindResult = "Lua";
    return 1;
  }
  i = lua_gettop (Lua);
  if (i)
  {
    ERROR ("Lua:binding_lua: stack isn't empty, %d elements in it.", i);
    lua_settop (Lua, 0);			/* reset stack */
  }
  if (!_lua_getbindlist (Lua, "*") || /* B */
      !_lua_getbinding (Lua, 1, name))		/* push function onto stack */
  {
    ERROR ("Lua:binding_lua: binding %s not found.", name);
    lua_settop (Lua, 0);
    return 0;
  }
  lua_remove (Lua, 1); /* n f */
  lua_remove (Lua, 1); /* f */
  while (i < argc)
    lua_pushstring (Lua, argv[i++]);		/* push parameters onto stack */
  i = lua_pcall (Lua, argc, 1, 0);		/* run Lua binding */
  if (i == 0)					/* no errors */
  {
    BindResult = (char *)lua_tostring (Lua, 1);	/* get a value */
    if (lua_isnumber (Lua, 1))
      i = lua_tonumber (Lua, 1);
    lua_pushstring (Lua, "BindResult");		/* variable name */
    lua_insert (Lua, 1);			/* swap with result */
    lua_settable (Lua, LUA_REGISTRYINDEX);	/* keep it in registry */
    return i;
  }
  BindResult = NULL;
  if (i == LUA_ERRRUN)
    ERROR ("Lua: runtime error on call \"%s\" with %d args: %s.", name, argc,
	   lua_tostring (Lua, 1));
  else if (i == LUA_ERRMEM)
    ERROR ("Lua: memory error on call \"%s\" with %d args: %s.", name, argc,
	   lua_tostring (Lua, 1));
  else
    ERROR ("Lua: unknown error %d on call \"%s\" with %d args: %s.", i, name,
	   argc, lua_tostring (Lua, 1));
  lua_pop (Lua, 1);
  return 0;
}

BINDING_TYPE_script (script_lua);
static int script_lua (char *filename)
{
  int i;

  i = luaL_loadfile (Lua, filename);
  if (i == LUA_ERRFILE &&		/* file not found */
      !strchr (filename, '/'))		/* and relative path? try SCRIPTSDIR */
  {
    char fn[LONG_STRING];

    lua_pop (Lua, 1);			/* delete error message from stack */
    Add_Request (I_LOG, "*", F_WARN,
		 "Lua: file %s not found, trying default path.", filename);
    strfcpy (fn, SCRIPTSDIR "/", sizeof(fn));
    strfcat (fn, filename, sizeof(fn));
    i = luaL_loadfile (Lua, fn);
  }
  if (i == 0 && !lua_pcall (Lua, 0, 0, 0))
  {
    if (lua_gettop (Lua))
    {
      ERROR ("Lua: execute of %s has %d results on return, first one is %s, string value of it is: %s.",
	     filename, lua_gettop (Lua), lua_typename (Lua, lua_type (Lua, 1)),
	     lua_tostring (Lua, 1));
      lua_settop (Lua, 0);
    }
    return 1;
  }
  ERROR ("Lua error on loading %s: %s.", filename, lua_tostring (Lua, 1));
  lua_pop (Lua, 1);
  return 0;
}


/*
 * Calls from Lua to FoxEye:
 *   static int func(lua_State *L);
 */
static NODE *lua_bindtables = NULL;

static int _lua_find_binding (lua_State *L, int n, const char *t) /* f -> f n f */
{
  char name[STRING];
  int i;

  if (_lua_getbinding (L, n, t) && lua_equal (L, -1, -3)) /* f name f2 */
    return 1;
  i = 0;
  FOREVER
  {
    lua_pop (L, 2); /* f */
    if (i++ == 999)
      luaL_error (L, "incorrectable error in bind for %s, is it cycled?", t);
    snprintf (name, sizeof(name), "%s#%d", t, i);
    DBG ("lua:_lua_find_binding: trying %s", name);
    if (!_lua_getbinding (L, n, name)) /* f name f2 */
      return 0;
    if (lua_equal (L, -1, -3))
      return 1;
  }
  /* never reached */
}

static void _lua_try_binds (lua_State *L, int n, const char *t) /* f -> f name */
{
  int i = _lua_find_binding (L, n, t); /* f name f/nil */

  DBG ("lua:_lua_try_binds: stack check: %d: %s(%s) %s", lua_gettop (L),
       lua_typename (Lua, lua_type (Lua, -1)), lua_tostring (L, -1),
       lua_typename (Lua, lua_type (Lua, -2)));
  lua_pop (L, 1); /* f name */
  DBG ("lua:_lua_try_binds: _lua_find_binding returns %d and %s, stack %d", i,
       lua_tostring (L, -1), lua_gettop (L));
  if (i)
    return;
  lua_pushvalue (L, -1); /* f name name */
  lua_pushvalue (L, -3); /* f name name f */
  lua_settable (L, n); /* f name */
  DBG ("lua:_lua_try_binds: stack check: %d: %s(%s) %s", lua_gettop (L),
       lua_typename (Lua, lua_type (Lua, -1)), lua_tostring (L, -1),
       lua_typename (Lua, lua_type (Lua, -2)));
}

static void _lua_getflags (lua_State *L, int n, userflag *gf, userflag *cf)
{
  const char *fs = lua_tostring (L, n);

  *gf = strtouserflag (fs, (char **)&fs);
  if (*fs == '&')		/* x&y */
    *cf = U_AND | strtouserflag (&fs[1], NULL);
  else if (*fs == '|')		/* x[|y] */
    *cf = strtouserflag (&fs[1], NULL);
  else
    *cf = 0;
}

static int _lua_bind (lua_State *L) /* foxeye.bind(table,mask,uflags,func) */
{
  lua_Debug dbg;
  const char *table, *mask;
  userflag guf, cuf;

  if (lua_gettop (L) != 4)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
  luaL_argcheck (L, lua_isstring (L, 3), 3, NULL);
  luaL_argcheck (L, lua_isfunction (L, 4), 4, NULL);
  if (!_lua_getbindlist (L, "*")) /* t m u f A */
    return luaL_error (L, "incorrectable binding error");
  lua_insert (L, 4); /* t m u A f */
  table = lua_tostring (L, 1);
  mask = lua_tostring (L, 2);
  _lua_getflags (L, 3, &guf, &cuf);
  lua_pushvalue (L, -1); /* t m u A f f */
  lua_getinfo (L, ">n", &dbg); /* t m u A f */
  DBG ("lua:lua_bind: stack check: %d: %s(%s) %s %s", lua_gettop (L),
       lua_typename (Lua, lua_type (Lua, -3)), lua_tostring (L, -3),
       lua_typename (Lua, lua_type (Lua, -2)),
       lua_typename (Lua, lua_type (Lua, -1)));
  if (dbg.name)		/* bingo! it have a name! */
    _lua_try_binds (L, 4, dbg.name); /* t m u A f n */
  else			/* it's unnamed function, let's name it as binding#x */
    _lua_try_binds (L, 4, "binding"); /* t m u A f n */
  /* it's inserted into common list not individual one */
  _lua_getbindlist (L, table); /* t m u A f n B */
  lua_replace (L, 4); /* t m u B f n */
  table = safe_strdup (table);
  dprint (3, "lua:lua_bind: table %s mask %s func %s", table, mask,
	  lua_tostring (L, 6));
  if (!Add_Binding (table, mask, guf, cuf, &binding_lua, lua_tostring (L, 6)))
  {
    Add_Request (I_LOG, "*", F_WARN, "Lua: duplicate binding attempt to %s.",
		 lua_tostring (L, 6));
  }
  if (Insert_Key (&lua_bindtables, table, (void *)table, 1))
    safe_free ((void *)table); /* it's not added (already in list) so free memory */
  lua_insert (L, 5); /* t m u B n f */
  lua_settable (L, 4); /* t m u B */
  /* and now it's added into individual list too */
  return 0;
}

static int _lua_unbind (lua_State *L) /* foxeye.unbind(table[,func]) */
{
  lua_Debug dbg;
  const char *table;

  if (lua_gettop (L) < 1 || lua_gettop (L) > 2)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  table = lua_tostring (L, 1);
  if (lua_gettop (L) == 2)		/* remove one function */
  {
    luaL_argcheck (L, lua_isfunction (L, 2), 2, NULL);
    lua_pushvalue (L, 2); /* t f f */
    lua_getinfo (L, ">n", &dbg); /* t f */
    if (!dbg.name || !_lua_getbindlist (L, table)) /* t f B */
      return luaL_error (L, "incorrectable binding error");
    lua_insert (L, 2); /* t B f */
    dprint (5, "lua:_lua_unbind: deleting binding %s.", dbg.name);
    if (_lua_find_binding (L, 2, dbg.name)) /* t B f n f */
      Delete_Binding (table, &binding_lua, lua_tostring (L, 4));
    lua_pop (L, 1); /* t B f n */
    lua_pushvalue (L, -1); /* t B f n n */
    lua_pushnil (L); /* t B f n n nil */
    lua_rawset (L, 2); /* t B f n */
    /* cleared from individual table... scanning others! */
    if (_lua_scanbindlists (L, 4) == 0)
    {
      _lua_getbindlist (L, "*"); /* t B f n A */
      lua_replace (L, 2); /* t A f n */
      lua_pushnil (L); /* t A f n nil */
      lua_rawset (L, 2); /* t A f */
      /* and now cleared from common table too */
      dprint (3, "lua:_lua_unbind: deleted from common list.");
    }
  }
  else					/* remove all functions */
  {
    Delete_Binding (table, &binding_lua, NULL); /* clear bindtable */
    /* remove all from Lua */
    if (!_lua_getbindlist (L, table)) /* t B */
      return luaL_error (L, "incorrectable binding error");
    _lua_getbindlist (L, "*"); /* t B A */
    lua_pushnil (L); /* t B A nil */
    while (lua_next (L, 2)) /* t B A k f */
    {
      lua_getinfo (L, ">n", &dbg); /* t B A k */
      DBG ("lua:_lua_unbind: checking name %s.", dbg.name);
      if (!dbg.name)
	continue;			/* OUCH! we lost it! */
      lua_pushstring (L, dbg.name); /* t B A k n */
      if (_lua_scanbindlists (L, 5) == 1) /* clear it from common list */
      {
	lua_pushnil (L); /* t B A k n nil */
	lua_settable (L, 3); /* t B A k */
	dprint (3, "lua:_lua_unbind: deleted from common list.");
      }
      else
	lua_pop (L, 1); /* t B A k */
    } /* t B A */
    _lua_clearbindlist (L, 1);
  }
  return 0;
}

static int _lua_nick (lua_State *L) /* nick = foxeye.client.nick(client) */
{
  register const char *c, *e;

  if (lua_gettop (L) != 1)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  c = lua_tostring (L, 1);
  e = strrchr (c, '@');
  if (e)
    lua_pushlstring (L, c, e - c);
  else
    lua_pushstring (L, c);
  dprint (5, "lua:_lua_nick(%s)", c);
  return 1;
}

static int _lua_sendto (lua_State *L, iftype_t to, flag_t fl)
{
  const char *target;

  if (lua_gettop (L) != 2)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
  target = lua_tostring (L, 1);
  if (to == I_CLIENT && target[0] == ':')
    to = I_DCCALIAS;	/* sending to direct service/botnet */
  Add_Request (to, target, fl, "%s", lua_tostring (L, 2));
  return 0;
}

static int _lua_log (lua_State *L) /* foxeye.log(where,text) */
{
  return _lua_sendto (L, I_LOG, F_WARN);
}

static int _lua_send (lua_State *L) /* net.send(network,message) */
{
  return _lua_sendto (L, I_SERVICE, 0);
}

static int _lua_message (lua_State *L) /* net.message(client,text) */
{
  return _lua_sendto (L, I_CLIENT, F_T_MESSAGE);
}

static int _lua_notice (lua_State *L) /* net.notice(client,text) */
{
  return _lua_sendto (L, I_CLIENT, F_T_NOTICE);
}

static int _lua_version (lua_State *L) /* ver = foxeye.version() */
{
  if (lua_gettop (L))
    return luaL_error (L, "function should have no parameters");
  lua_pushstring (L, VERSION);
  return 1;
}

static int _lua_error (lua_State *L) /* foxeye.error(text) */
{
  if (lua_gettop (L) != 1)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  ERROR ("%s", lua_tostring (L, 1));
  return 0;
}

static int _lua_debug (lua_State *L) /* foxeye.debug(text) */
{
  if (lua_gettop (L) != 1)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  dprint (2, "%s", lua_tostring (L, 1));
  return 0;
}

static int _lua_event (lua_State *L) /* foxeye.event(type,lname[,value]) */
{
  lid_t id;
  int num;

  if (lua_gettop (L) < 2 || lua_gettop (L) > 3)
    return luaL_error (L, "bad number of parameters");
  dprint (5, "lua:_lua_event.");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
  id = FindLID (lua_tostring (L, 2));
  if (id == ID_REM)
    return luaL_error (L, "name \"%s\" isn't registered", lua_tostring (L, 2));
  if (lua_gettop (L) == 3)
  {
    luaL_argcheck (L, lua_isnumber (L, 3), 3, NULL);
    num = lua_tonumber (L, 3);
    if (num < SHRT_MIN || num > SHRT_MAX)
      luaL_error (L, "value %d is out of range", num);
  }
  else
    num = 0;
  NewEvent (Event (lua_tostring (L, 1)), ID_ANY, id, (short)num);
  return 0;
}

static int _lua_efind (lua_State *L) /* time,value = foxeye.EFind(type,lname[,time]) */
{
  struct wtmp_t wtmp;
  time_t t;

  if (lua_gettop (L) < 2 || lua_gettop (L) > 3)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
  if (lua_gettop (L) == 3)
  {
    luaL_argcheck (L, lua_isnumber (L, 3), 3, NULL);
    t = lua_tonumber (L, 3);
  }
  else
    t = 0;
  if (FindEvent (&wtmp, lua_tostring (L, 2), Event (lua_tostring (L, 1)),
		 ID_ANY, t))
    return luaL_error (L, "wtmp searching error");
  lua_pushnumber (L, wtmp.time);
  lua_pushnumber (L, (int)wtmp.count);
  return 2;
}

static int _lua_ison (lua_State *L) /* nick = net.ison(serv[,lname]) */
{
  const char *lname;

  if (lua_gettop (L) < 1 || lua_gettop (L) > 2)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  if (lua_gettop (L) == 2)
  {
    luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
    lname = lua_tostring (L, 2);
  }
  else
    lname = NULL;
  if (!Lname_IsOn (lua_tostring (L, 1), NULL, lname, &lname))
    lname = NULL;
  if (lname)
    lua_pushstring (L, lname);
  else
    lua_pushnil (L);
  return 1;
}

static int _lua_check (lua_State *L) /* time,host,lname = net.check(net[,serv[,nick]]) */
{
  const char *lname, *host, *serv;
  time_t t;

  if (lua_gettop (L) < 1 || lua_gettop (L) > 3)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  if (lua_gettop(L) == 3) {
    luaL_argcheck (L, lua_isstring (L, 3), 3, NULL);
    lname = lua_tostring (L, 3);
    if (lua_isstring(L, 2))
      serv = lua_tostring (L, 2);
    else
      serv = NULL;
  } else if (lua_gettop (L) == 2)
  {
    luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
    lname = lua_tostring (L, 2);
    serv = NULL;
  }
  else
    lname = serv = NULL;
  if (!Inspect_Client (lua_tostring (L, 1), serv, lname, &lname, &host, &t, NULL))
  {
    lname = NULL;
    host = NULL;
    t = 0;
  }
  lua_pushnumber (L, t);
  lua_pushstring (L, NONULL(host));
  if (lname)
    lua_pushstring (L, lname);
  else
    lua_pushnil (L);
  return 3;
}

typedef struct lua_timer
{
  tid_t tid;
  time_t when;
  char *cmd;
  struct lua_timer *prev;
} lua_timer;

ALLOCATABLE_TYPE (lua_timer, LT_, prev)

static lua_timer *Lua_Last_Timer = NULL;

static int _lua_timer (lua_State *L) /* tid = SetTimer(time,func) */
{
  int n;
  lua_Debug dbg;
  lua_timer *tt;

  if (lua_gettop (L) != 2)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isnumber (L, 1), 1, NULL);
  luaL_argcheck (L, lua_isfunction (L, 2), 2, NULL);
  n = lua_tonumber (L, 1);
  lua_getinfo (L, ">n", &dbg); /* t */
  if (!dbg.name)
    return luaL_error (L, "cannot get function name for SetTimer");
  if (n < 0 || n > _lua_max_timer)
    return luaL_error (L, "invalid parameters for SetTimer");
  tt = alloc_lua_timer();
  tt->tid = NewTimer (I_MODULE, "lua", S_LOCAL, (unsigned int)n, 0, 0, 0);
  tt->cmd = safe_strdup (dbg.name);
  tt->when = Time + n;
  tt->prev = Lua_Last_Timer;
  Lua_Last_Timer = tt;
  dprint (3, "tcl:_lua_timer:added timer for %lu", (unsigned long int)tt->when);
  lua_pushnumber (L, tt->tid);
  return 1;
}

static int _lua_untimer (lua_State *L) /* ResetTimer(tid) */
{
  int n;
  lua_timer *tt, **ptt;

  if (lua_gettop (L) != 1)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isnumber (L, 1), 1, NULL);
  n = lua_tonumber (L, 1);
  for (ptt = &Lua_Last_Timer; (tt = *ptt); ptt = &tt->prev)
    if ((int)tt->tid == n)
      break;
  if (!tt)
    return luaL_error (L, "this timer-id is not active");
  *ptt = tt->prev;
  KillTimer (tt->tid);
  FREE (&tt->cmd);
  /* do we need some garbage gathering for lua here? */
  dprint (3, "lua:_lua_untimer:removed timer for %lu", (unsigned long int)tt->when);
  free_lua_timer (tt);
  return 0;
}

typedef struct
{
  lua_State *L;
  int n;
} lua_r_data;

static int _lua_receiver (INTERFACE *iface, REQUEST *req)
{
  if (req)
  {
    lua_r_data *d = iface->data;
    char *c, *cc;

    c = req->string;
    if (*c) do {
      cc = gettoken (c, NULL);
      lua_pushinteger (d->L, d->n++); /* ... t n */
      lua_pushstring (d->L, c); /* ... t n v */
      lua_rawset (d->L, -3); /* ... t */
      c = cc;
    } while (*c);
  }
  return REQ_OK;
}

static int _lua_cfind (lua_State *L) /* list = find(mask[,flag[,field]]) */
{
  int n = lua_gettop (L);
  const char *mask, *field;
  userflag f;
  INTERFACE *tmp;

  if (n < 1 || n > 3)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  if (n > 1)
    luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
  if (n > 2)
    luaL_argcheck (L, lua_isstring (L, 3), 3, NULL);
  mask = lua_tostring (L, 1);
  if (n > 1)
    f = strtouserflag (lua_tostring (L, 2), NULL);
  else
    f = 0;
  if (n > 2)
    field = lua_tostring (L, 3);
  else
    field = NULL;
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_lua_receiver, NULL);
  n = Get_Clientlist (tmp, f, field, mask);
  if (n)
  {
    tmp->data = safe_malloc (sizeof(lua_r_data));
    lua_newtable (L); /* ... t */
    ((lua_r_data *)tmp->data)->n = 1;
    ((lua_r_data *)tmp->data)->L = L;
    Set_Iface (tmp);
    while (Get_Request()); /* push everything there */
    Unset_Iface();
  }
  else
    lua_pushnil (L);
  tmp->ift = I_DIED;
  return 1;
}

static int _lua_chosts (lua_State *L) /* list = hosts(lname) */
{
  INTERFACE *tmp;

  if (lua_gettop (L) != 1)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_lua_receiver, NULL);
  if (Get_Hostlist (tmp, FindLID (lua_tostring (L, 1))))
  {
    tmp->data = safe_malloc (sizeof(lua_r_data));
    lua_newtable (L); /* ... t */
    ((lua_r_data *)tmp->data)->n = 1;
    ((lua_r_data *)tmp->data)->L = L;
    Set_Iface (tmp);
    while (Get_Request()); /* push everything there */
    Unset_Iface();
  }
  else
    lua_pushnil (L);
  tmp->ift = I_DIED;
  return 1;
}

static int _lua_cinfos (lua_State *L) /* list = infos(lname) */
{
  INTERFACE *tmp;

  if (lua_gettop (L) != 1)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_lua_receiver, NULL);
  if (Get_Fieldlist (tmp, FindLID (lua_tostring (L, 1))))
  {
    tmp->data = safe_malloc (sizeof(lua_r_data));
    lua_newtable (L); /* ... t */
    ((lua_r_data *)tmp->data)->n = 1;
    ((lua_r_data *)tmp->data)->L = L;
    Set_Iface (tmp);
    while (Get_Request()); /* push everything there */
    Unset_Iface();
  }
  else
    lua_pushnil (L);
  tmp->ift = I_DIED;
  return 1;
}

static int _lua_chave (lua_State *L) /* x = have(lname[,serv[,flag]]) */
{
  struct clrec_t *client;
  const char *srv = NULL, *flstr = NULL;
  userflag uf;
  char buff[64];

  dprint (5, "lua:_lua_chave()");
  uf = (userflag)lua_gettop (L);	/* use it temporary */
  if (uf < 1 || uf > 3)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  /* save values and never call Lua when record is locked */
  if (uf > 1 && !lua_isnil (L, 2))
  {
    luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
    srv = lua_tostring (L, 2);
  }
  if (uf > 2)
  {
    luaL_argcheck (L, lua_isstring (L, 3), 3, NULL);
    flstr = lua_tostring (L, 3);
  }
  if (!(client = Lock_Clientrecord (lua_tostring (L, 1))))
    return luaL_error (L, "no such client name known");
  uf = Get_Flags (client, srv);
  if (flstr)				/* 'set' form of function */
  {
    if (*flstr == '-')
      uf &= ~(strtouserflag (&flstr[1], NULL));
    else if (*flstr == '+')
      uf |= strtouserflag (&flstr[1], NULL);
    else
      uf = strtouserflag (flstr, NULL);
    uf = Set_Flags (client, srv, uf);
  }
  Unlock_Clientrecord (client);
  lua_pushstring (L, userflagtostr (uf, buff));
  return 1;
}

static int _lua_cset (lua_State *L) /* set(lname,field[,value]) */
{
  struct clrec_t *client;
  const char *field, *val;
  int n;

  dprint (5, "lua:_lua_cset()");
  n = lua_gettop (L);
  if (n < 2 || n > 3)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
  /* save values and never call Lua when record is locked */
  if (n > 2 && !lua_isnil (L, 3))
  {
    luaL_argcheck (L, lua_isstring (L, 3), 3, NULL);
    val = lua_tostring (L, 3);
  }
  else
    val = NULL;
  field = lua_tostring (L, 2);
  if (!(client = Lock_Clientrecord (lua_tostring (L, 1))))
    return luaL_error (L, "no such client name known");
  /* TODO: can we set expiration time on field? */
  if (!Set_Field (client, field, val, 0))
  {
    Unlock_Clientrecord (client);
    return luaL_error (L, "could not set field for client");
  }
  Unlock_Clientrecord (client);
  return 0; /* success */
}

static int _lua_cget (lua_State *L) /* val,flag,time = get(lname,field) */
{
  struct clrec_t *client;
  const char *field, *val;
  time_t exp = 0;
  userflag uf;
  char buff[64];

  dprint (5, "lua:_lua_cget()");
  if (lua_gettop (L) != 2)  
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  if (lua_isnil (L, 2))
    field = NULL;
  else
  {
    luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
    field = lua_tostring (L, 2);
  }
  if (!(client = Lock_Clientrecord (lua_tostring (L, 1))))
    return luaL_error (L, "no such client name known");
  val = strrchr (field, '@');
  if (val)
    uf = Get_Flags (client, (val == field) ? &field[1] : field);
  else
    uf = 0;
  val = safe_strdup (Get_Field (client, field, &exp));
  Unlock_Clientrecord (client);
  if (!val)
    lua_pushnil (L);
  else
    lua_pushstring (L, val);
  lua_pushstring (L, userflagtostr (uf, buff));
  lua_pushinteger (L, exp);
  FREE (&val);
  return 3;
}

static const luaL_Reg luatable_foxeye[] = {
  { "bind", &_lua_bind },
  { "unbind", &_lua_unbind },
  { "log", &_lua_log },
  { "error", &_lua_error },
  { "debug", &_lua_debug },
  { "event", &_lua_event },
  { "EFind", &_lua_efind },
  { "SetTimer", &_lua_timer },
  { "ResetTimer", &_lua_untimer },
//  { "GetFormat", &_lua_fget }, // GetFormat : fmt = GetFormat(name)
//  { "SetFormat", &_lua_fset }, // SetFormat : SetFormat(name,fmt)
  { "version", &_lua_version },
  { NULL, NULL }
};

static const luaL_Reg luatable_foxeye_client[] = {
  { "nick", &_lua_nick },
  { "find", &_lua_cfind },
  { "have", &_lua_chave },
//  { "add", &_lua_cadd }, // Add_Clientrecord : add(lname,mask,flag)
//  { "delete", &_lua_cdelete }, // Delete_Clientrecord : delete(lname)
  { "set", &_lua_cset },
  { "get", &_lua_cget },
  { "hosts", &_lua_chosts },
  { "infos", &_lua_cinfos },
  { NULL, NULL }
};

static const luaL_Reg luatable_net[] = {
  { "ison", &_lua_ison },
  { "check", &_lua_check },
  { "send", &_lua_send },
  { "message", &_lua_message },
  { "notice", &_lua_notice },
  { NULL, NULL }
};


/*
 * registering data and functions into Lua
 */
static int lua_call_function (lua_State *L) /* int = func(arg) */
{
  int (*fn) (const char *);
  register int i;

  // args: [1] string
  // pseudo-indices: [1] (void *)int (*)(char *)
  if (!lua_isstring (Lua, 1) ||
      !lua_islightuserdata (Lua, lua_upvalueindex (1)))
    return luaL_error (Lua, "incorrect function call");
  BindResult = NULL;
  fn = (Function)lua_touserdata (Lua, lua_upvalueindex (1));
  i = fn (lua_tostring (Lua, 1));
  if (i != 0 && BindResult != NULL)
    lua_pushstring (Lua, BindResult);
  else
    lua_pushinteger (Lua, i);
  return 1;
}

#define _lua_getdata(_l,_n) lua_pushstring(_l, "__data"); /* d */ \
			    lua_rawget(_l, _n); /* D */ \
			    if (!lua_istable(_l, -1)) \
			      return luaL_error(_l, "there is no data array")

static void _lua_fe_name (const char *name)
{
  char s[STRING];
  register char *t = s;
  register const char *tt = name;

  if (tt)
    while (*tt && t < &s[sizeof(s)-1])
    {
      if (*tt == '-') *t++ = '_';
      else *t++ = *tt;
      tt++;
    }
  *t = '\0';
  lua_pushstring (Lua, s);
}

BINDING_TYPE_function (lua_register_function);
static int lua_register_function (const char *name, int (*fn) (const char *))
{
  _lua_getfoxeye (Lua); /* T */
  _lua_fe_name (name); /* T k */		/* convert name /-/_/ */
  lua_pushlightuserdata (Lua, (void *)fn); /* T k f */
  lua_pushcclosure (Lua, &lua_call_function, 1); /* T k d */
  dprint (5, "lua:lua_register_function: registering \"%s\"",
	  lua_tostring (Lua, 2));
  lua_rawset (Lua, 1); /* T */
  lua_pop (Lua, 1);
  return 1;
}

BINDING_TYPE_unfunction (lua_unregister_function);
static int lua_unregister_function (const char *name)
{
  _lua_getfoxeye (Lua); /* T */
  _lua_fe_name (name); /* T k */		/* convert name /-/_/ */
  lua_pushvalue (Lua, 2); /* T k k */
  lua_rawget (Lua, 1); /* T k T[k] */
  if (!lua_iscfunction (Lua, 3))
  {
    lua_pop (Lua, 3);
    return 0;
  }
  lua_pop (Lua, 1); /* T k */
  lua_pushnil (Lua); /* T k nil */
  dprint (5, "lua:lua_unregister_function: unregistering \"%s\"",
	  lua_tostring (Lua, 2));
  lua_rawset (Lua, 1); /* T */
  lua_pop (Lua, 1);
  return 1;
}

typedef struct {
  void *ptr;
  size_t s;
} lua_fedata_t;

static int lua_get_fevar (lua_State *L) /* t k -> t t[k] : x = a[b] */
{
  lua_fedata_t *data;
  int n = lua_gettop(L); /* t k // n is index of k */

  DBG("lua:lua_get_fevar: stack is %d (should be 2)", n);
  _lua_getdata (L, n - 1); /* T k D */
  lua_pushvalue (L, n); /* T k D k */
  lua_rawget (L, n + 1); /* T k D D[k] */
  data = lua_touserdata (L, -1);
  if (!data)
    return luaL_error (L, "variable foxeye.%s is unknown", lua_tostring (L, n));
  lua_pop (L, 3); /* T */
  switch (data->s)
  {
    case 0: /* long int */
      lua_pushinteger (L, *(long int *)data->ptr); /* T t[k] */
      break;
    case 1: /* bool */
      lua_pushboolean (L, (*(bool *)data->ptr & TRUE) ? 1 : 0); /* T t[k] */
      break;
    default: /* string */
      lua_pushstring (L, (char *)data->ptr); /* T t[k] */
  }
  return 1;
}

static int lua_set_fevar (lua_State *L) /* T k v -> T (T[k]=v) : a[b] = c */
{
  lua_fedata_t *data;
  char *msg = NULL;
  int n = lua_gettop(L); /* t k v // n is index of v */

  DBG("lua:lua_set_fevar: stack is %d (should be 3)", n);
  _lua_getdata (L, n - 2); /* T k v D */
  lua_pushvalue (L, n - 1); /* T k v D k */
  lua_rawget (L, n + 1); /* T k v D D[k] */
  data = lua_touserdata (L, -1);
  if (!data)
    msg = " is unknown";
  else switch (data->s)
  {
    case 0: /* long int */
      *(long int *)data->ptr = (long int)luaL_checklong (L, n);
      break;
    case 1: /* bool */
      luaL_checktype (L, n, LUA_TBOOLEAN);
      if (lua_toboolean (L, n))
	*(bool *)data->ptr |= TRUE;
      else
	*(bool *)data->ptr &= ~TRUE;
      break;
    case 2: /* r/o string */
      msg = " is unchangeable";
      break;
    default: /* string */
      strfcpy ((char *)data->ptr, luaL_checkstring (L, n), data->s);
  }
  if (msg)
    return luaL_error (L, "variable foxeye.%s%s", lua_tostring (L, n - 1), msg);
  lua_pop (L, 4); /* T */
  return 0;
}

static const luaL_Reg luatable_vars[] = {
  { "__index", lua_get_fevar },
  { "__newindex", lua_set_fevar },
  { NULL, NULL }
};

BINDING_TYPE_register (lua_register_variable);
static int lua_register_variable (const char *name, void *var, size_t size)
{
  lua_fedata_t *data;

  _lua_getfoxeye (Lua); /* T */
  _lua_getdata (Lua, 1); /* T D */
  _lua_fe_name (name); /* T D k */
  data = lua_newuserdata (Lua, sizeof(lua_fedata_t)); /* T D k v */
  data->ptr = var;
  data->s = size;
  dprint (5, "lua:lua_register_variable: registering \"%s\" (%p[%d]) into %p",
	  lua_tostring (Lua, 3), var, (int)size, data);
  lua_rawset (Lua, 2); /* T D */
  lua_pop (Lua, 2); /* */
  return 1;
}

BINDING_TYPE_unregister (lua_unregister_variable);
static int lua_unregister_variable (const char *name)
{
  _lua_getfoxeye (Lua); /* T */
  _lua_getdata (Lua, 1); /* T D */
  _lua_fe_name (name); /* T D k */		/* convert name /-/_/ */
  lua_pushvalue (Lua, 3); /* T D k k */
  lua_rawget (Lua, 2); /* T D k D[k] */
  if (!lua_isuserdata (Lua, -1))
  {
    lua_pop (Lua, 4);
    return 0;
  }
  lua_pop (Lua, 1); /* T D k */
  lua_pushnil (Lua); /* T D k nil */
  dprint (5, "lua:lua_unregister_variable: unregistering \"%s\"",
	  lua_tostring (Lua, 3));
  lua_rawset (Lua, 2); /* T D */
  lua_pop (Lua, 2);
  return 1;
}


BINDING_TYPE_dcc (dc_lua);
static int dc_lua (struct peer_t *from, char *args)
{
  if (!args)
    return 0;
  if (luaL_loadstring(Lua, args) || lua_pcall(Lua, 0, LUA_MULTRET, 0))
  {
    New_Request (from->iface, 0, "Lua: error in your input: %s.",
		 lua_tostring (Lua, 1));
    lua_settop (Lua, 0);
    return 0;
  }
  if (lua_gettop (Lua))
  {
    register const char *xx = lua_tostring(Lua, 1);

    if (xx != NULL)
      New_Request (from->iface, 0,
		   "Lua: execute of your input returned %d results, first one is %s, string value of it is: %s.",
		   lua_gettop (Lua), lua_typename (Lua, lua_type (Lua, 1)), xx);
    else
      New_Request (from->iface, 0,
		   "Lua: execute of your input returned %d results, first one is %s.",
		   lua_gettop (Lua), lua_typename (Lua, lua_type (Lua, 1)));
    lua_settop (Lua, 0);
  }
  else
    DBG ("lua:dc_lua:lua_pcall returned empty stack");
  return 1;
}


/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REG - (re)register all variables,
 *  S_REPORT - out state info to log.
 */
static iftype_t lua_module_signal (INTERFACE *iface, ifsig_t sig)
{
  LEAF *l;
  const char *c;
  INTERFACE *tmp;
  lua_timer *tt, **ptt;

  switch (sig)
  {
    case S_TERMINATE:
      Delete_Binding ("script", &script_lua, NULL);
      Delete_Binding ("register", &lua_register_variable, NULL);
      Delete_Binding ("function", &lua_register_function, NULL);
      Delete_Binding ("unregister", &lua_unregister_variable, NULL);
      Delete_Binding ("unfunction", &lua_unregister_function, NULL);
      Delete_Binding ("dcc", &dc_lua, NULL);
      UnregisterVariable ("lua-max-timer");
      l = NULL;
      while ((l = Next_Leaf (lua_bindtables, l, &c)))
	Delete_Binding (c, &binding_lua, NULL);	/* delete all bindings there */
      Destroy_Tree (&lua_bindtables, safe_pfree);
      lua_close (Lua);
      Delete_Help ("lua");
      iface->ift |= I_DIED;
      break;
    case S_REG:
      Add_Request (I_INIT, "*", F_REPORT, "module lua");
      RegisterInteger ("lua-max-timer", &_lua_max_timer);
      break;
    case S_REPORT:
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "Module lua: %u/%u timers active,", LT_num,
		   LT_max);
      New_Request (tmp, F_REPORT, "            interpreter using %d kB memory.",
		   lua_gc (Lua, LUA_GCCOUNT, 0));
      Unset_Iface();
      break;
    case S_LOCAL:
      for (ptt = &Lua_Last_Timer; (tt = *ptt); )
      {
	if (tt->when <= Time)
	{
	  lua_pushstring (Lua, tt->cmd); /* n */
	  lua_gettable (Lua, -1); /* f */
	  if (!lua_isfunction (Lua, -1))
	    ERROR ("Lua: timer: %s isn't function name.", tt->cmd);
	  else
	  {
	    register int i = lua_pcall (Lua, 0, 0, 0); /* run Lua binding */
	    if (i != 0)				/* no errors */
	    {
	      if (i == LUA_ERRRUN)
		ERROR ("Lua: timer: runtime error on call \"%s\": %s.", tt->cmd,
		       lua_tostring (Lua, 1));
	      else if (i == LUA_ERRMEM)
		ERROR ("Lua: timer: memory error on call \"%s\": %s.", tt->cmd,
		       lua_tostring (Lua, 1));
	      else
		ERROR ("Lua: timer: unknown error %d on call \"%s\": %s.", i,
		       tt->cmd, lua_tostring (Lua, 1));
	      lua_pop (Lua, 1);
	    }
	  }
	  *ptt = tt->prev;
	  KillTimer (tt->tid);
	  FREE (&tt->cmd);
	  /* do we need some garbage gathering for lua here? */
	  dprint (3, "lua: timer:removed timer for %lu", (unsigned long int)tt->when);
	  free_lua_timer (tt);
	}
	else
	  ptt = &tt->prev;
      }
      break;
    default: ;
  }
  return 0;
}

/*
 * this function called when you load a module.
 * Input: parameters string args.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
SigFunction ModuleInit (char *args)
{
  CheckVersion;
  Lua = luaL_newstate();
  luaL_openlibs (Lua);	/* open standard libraries */
#if LUA_VERSION_NUM > 501
  lua_newtable (Lua); /* T */
  luaL_setfuncs (Lua, luatable_foxeye, 0); /* T */
  lua_setglobal (Lua, "foxeye"); /* */
  lua_newtable (Lua);
  luaL_setfuncs (Lua, luatable_foxeye_client, 0);
  lua_setglobal (Lua, "foxeye.client");
  lua_newtable (Lua);
  luaL_setfuncs (Lua, luatable_net, 0);
  lua_setglobal (Lua, "net");
#else
  luaL_register (Lua, "foxeye", luatable_foxeye);
  luaL_register (Lua, "foxeye.client", luatable_foxeye_client);
  luaL_register (Lua, "net", luatable_net);
  lua_pop (Lua, 3);	/* remove three above from stack */
#endif
  lua_getglobal (Lua, "foxeye"); /* T */
  if (luaL_newmetatable (Lua, "fe_vars")) /* T m */
    /* set all methods here */
#if LUA_VERSION_NUM > 501
    luaL_setfuncs (Lua, luatable_vars, 0); /* T m */
#else
    luaL_register (Lua, NULL, luatable_vars); /* T m -- nothing to stack! */
#endif
  lua_setmetatable (Lua, 1); /* T */
  lua_pushstring (Lua, "__data"); /* T d */
  lua_newtable (Lua); /* T d D */
  lua_rawset (Lua, 1); /* T -- foxeye[__data]=D */
  lua_pushstring (Lua, "__binds"); /* T b */
  lua_newtable (Lua); /* T b B */
  lua_rawset (Lua, 1); /* T -- foxeye[__binds]=B */
  lua_pop (Lua, 1);
  Add_Binding ("script", "*.lua", 0, 0, &script_lua, NULL);
  Add_Binding ("register", NULL, 0, 0, &lua_register_variable, NULL);
  Add_Binding ("function", NULL, 0, 0, &lua_register_function, NULL);
  Add_Binding ("unregister", NULL, 0, 0, &lua_unregister_variable, NULL);
  Add_Binding ("unfunction", NULL, 0, 0, &lua_unregister_function, NULL);
  Add_Binding ("dcc", "lua", U_OWNER, U_NONE, &dc_lua, NULL);
  RegisterInteger ("lua-max-timer", &_lua_max_timer);
  Send_Signal (I_MODULE | I_INIT, "*", S_REG);
  Add_Help ("lua");
  return (&lua_module_signal);
}
#else	/* not HAVE_LIBLUA */
SigFunction ModuleInit (char *args)
{
  ERROR ("Cannot run LUA, lualib not found, sorry.");
  return NULL;
}
#endif
