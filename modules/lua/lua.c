/*
 * Copyright (C) 2006-2010  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#endif

#include "init.h"
#include "tree.h"
#include "direct.h"
#include "wtmp.h"

static lua_State *Lua = NULL;

#define _lua_getfoxeye(l) lua_getglobal(l, "foxeye"); /* T */ \
			  if (!lua_istable(l, -1)) return 0

static inline int _lua_getbindlist (lua_State *L) /* -> B */
{
  _lua_getfoxeye (L); /* T */
  lua_pushstring (L, "__binds"); /* T b */
  lua_rawget (L, -2); /* T B */
  lua_remove (L, -2); /* B */
  if (!lua_istable (L, -1))
    return 0;
  return 1;
}

static int _lua_getbinding (lua_State *L, int n, const char *name) /* -> n f */
{
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
static int binding_lua (char *name, int argc, char *argv[])
{
  int i = 0;

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
  if (!_lua_getbindlist (Lua) ||
      !_lua_getbinding (Lua, 1, name))		/* push function onto stack */
  {
    ERROR ("Lua:binding_lua: binding %s not found.", name);
    lua_settop (Lua, 0);
    return 0;
  }
  lua_remove (Lua, 1);
  lua_remove (Lua, 1);
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
  if (!luaL_loadfile (Lua, filename) && !lua_pcall (Lua, 0, 0, 0))
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
    if (i++ == 999)	/* TODO: free names on foxeye.unbind */
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
  if (!_lua_getbindlist (L)) /* t m u f B */
    return luaL_error (L, "incorrectable binding error");
  lua_insert (L, 4); /* t m u B f */
  table = lua_tostring (L, 1);
  mask = lua_tostring (L, 2);
  _lua_getflags (L, 3, &guf, &cuf);
  lua_pushvalue (L, -1); /* t m u B f f */
  lua_getinfo (L, ">n", &dbg); /* t m u B f */
  DBG ("lua:lua_bind: stack check: %d: %s(%s) %s %s", lua_gettop (L),
       lua_typename (Lua, lua_type (Lua, -3)), lua_tostring (L, -3),
       lua_typename (Lua, lua_type (Lua, -2)),
       lua_typename (Lua, lua_type (Lua, -1)));
  if (dbg.name)		/* bingo! it have a name! */
    _lua_try_binds (L, 4, dbg.name); /* t m u B f n */
  else			/* it's unnamed function, let's name it as binding#x */
    _lua_try_binds (L, 4, "binding"); /* t m u B f n */
  lua_remove (L, 4); /* t m u f n */
  table = strdup (table);
  DBG ("lua:lua_bind: table %s mask %s func %s", table, mask, lua_tostring (L, 5));
  Add_Binding (table, mask, guf, cuf, &binding_lua, lua_tostring (L, 5));
  if (Insert_Key (&lua_bindtables, table, (void *)table, 1))
    free ((void *)table); /* it's not added (already in list) so free memory */
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
    if (!dbg.name || !_lua_getbindlist (L)) /* t f B */
      return luaL_error (L, "incorrectable binding error");
    lua_insert (L, 2); /* t B f */
    if (_lua_find_binding (L, 2, dbg.name)) /* t B f n f */
      Delete_Binding (table, &binding_lua, lua_tostring (L, 4));
  }
  else					/* remove all functions */
    Delete_Binding (table, &binding_lua, NULL);
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
  return 1;
}

static int _lua_sendto (lua_State *L, iftype_t to, flag_t fl)
{
  if (lua_gettop (L) != 2)
    return luaL_error (L, "bad number of parameters");
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
  Add_Request (to, (char *)lua_tostring (L, 1), fl, "%s", lua_tostring (L, 2));
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
  luaL_argcheck (L, lua_isstring (L, 1), 1, NULL);
  luaL_argcheck (L, lua_isstring (L, 2), 2, NULL);
  id = GetLID (lua_tostring (L, 2));
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
  wtmp_t wtmp;
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
  if (!Lname_IsOn (lua_tostring (L, 1), lname, &lname))
    lname = NULL;
  lua_pushstring (L, NONULL(lname));
  return 1;
}

static int _lua_check (lua_State *L) /* time,host,lname = net.check(serv[,nick])*/
{
  const char *lname, *host;
  time_t t;

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
  if (!Inspect_Client (lua_tostring (L, 1), lname, &lname, &host, &t, NULL))
  {
    lname = NULL;
    host = NULL;
    t = 0;
  }
  lua_pushnumber (L, t);
  lua_pushstring (L, NONULL(host));
  lua_pushstring (L, NONULL(lname));
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
//  { "SetTimer", &_lua_timer }, // NewTimer : tid = SetTimer(time,func[,data])
//  { "ResetTimer", &_lua_untimer }, // KillTimer : ResetTimer(tid)
//  { "GetFormat", &_lua_fget },
//  { "SetFormat", &_lua_fset },
  { "version", &_lua_version },
  { NULL, NULL }
};

static const luaL_Reg luatable_foxeye_client[] = {
  { "nick", &_lua_nick },
//  { "find", &_lua_cfind }, // Get_Clientlist : list = find(mask[,flag[,field]])
//  { "have", &_lua_chave }, // Get_Clientflags : x = have(lname,flag[,serv])
//  { "add", &_lua_cadd }, // Add_Clientrecord : add(lname,mask,flag)
//  { "delete", &_lua_cdelete }, // Delete_Clientrecord : delete(lname)
//  { "set", &_lua_cset }, // *Set_Field : set(lname,field[,value])
//  { "get", &_lua_cget }, // *Get_Field : val,flag,time = get(lname,field)
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
  int (*fn) (char *);
  register int i;

  // args: [1] string
  // pseudo-indices: [1] (void *)int (*)(char *)
  if (!lua_isstring (Lua, 1) ||
      !lua_islightuserdata (Lua, lua_upvalueindex (1)))
    return luaL_error (Lua, "incorrect function call");
  fn = lua_touserdata (Lua, lua_upvalueindex (1));
  i = fn ((char *)lua_tostring (Lua, 1));
  lua_pushinteger (Lua, i);
  return 1;
}

#define _lua_getdata(l,n) lua_pushstring(l, "__data"); /* d */ \
			  lua_rawget(l, n); /* D */ \
			  if (!lua_istable(l, -1)) \
			    return luaL_error(l, "there is no data array")

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
static int lua_register_function (const char *name, int (*fn) (char *))
{
  _lua_getfoxeye (Lua); /* T */
  _lua_fe_name (name); /* T k */		/* convert name /-/_/ */
  lua_pushlightuserdata (Lua, (void *)fn); /* T k f */
  lua_pushcclosure (Lua, &lua_call_function, 1); /* T k d */
  DBG ("lua_register_function: registering \"%s\"", lua_tostring (Lua, 2));
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
  DBG ("lua_unregister_function: unregistering \"%s\"", lua_tostring (Lua, 2));
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

  _lua_getdata (L, 1); /* T k D */
  lua_pushvalue (L, 2); /* T k D k */
  lua_rawget (L, 2); /* T k D D[k] */
  data = lua_touserdata (L, -1);
  if (!data)
    return luaL_error (L, "variable foxeye.%s is unknown.", lua_tostring (L, 2));
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
      lua_pushstring (L, (char *)data); /* T t[k] */
  }
  return 1;
}

static int lua_set_fevar (lua_State *L) /* T k v -> T (T[k]=v) : a[b] = c */
{
  lua_fedata_t *data;
  char *msg = NULL;

  _lua_getdata (L, 1); /* T k v D */
  lua_pushvalue (L, 2); /* T k v D k */
  lua_rawget (L, 4); /* T k v D D[k] */
  data = lua_touserdata (L, -1);
  if (!data)
    msg = " is unknown";
  else switch (data->s)
  {
    case 0: /* long int */
      *(long int *)data->ptr = luaL_checklong (L, 3);
      break;
    case 1: /* bool */
      luaL_checktype (L, 3, LUA_TBOOLEAN);
      if (lua_toboolean (L, 3))
	*(bool *)data->ptr |= TRUE;
      else
	*(bool *)data->ptr &= ~TRUE;
      break;
    case 2: /* r/o string */
      msg = " is unchangeable";
      break;
    default: /* string */
      strfcpy ((char *)data->ptr, luaL_checkstring (L, 3), data->s);
  }
  if (msg)
    return luaL_error (L, "variable foxeye.%s%s.", lua_tostring (L, 2), msg);
  lua_pop (L, 4); /* T */
  return 0;
}

static const luaL_reg luatable_vars[] = {
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
  DBG ("lua_register_variable: registering \"%s\"", lua_tostring (Lua, 3));
  lua_rawset (Lua, 2); /* T D */
  lua_pop (Lua, 2); /* */
  return 1;
}

BINDING_TYPE_unregister (lua_unregister_variable);
static int lua_unregister_variable (const char *name)
{
  lua_fedata_t *data;

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
  data = lua_touserdata (Lua, -1);
  lua_pop (Lua, 1); /* T D k */
  lua_pushnil (Lua); /* T D k nil */
  DBG ("lua_unregister_variable: unregistering \"%s\"", lua_tostring (Lua, 3));
  lua_rawset (Lua, 2); /* T D */
  lua_pop (Lua, 2);
  return 1;
}


BINDING_TYPE_dcc (dc_lua);
static int dc_lua (peer_t *from, char *args)
{
  if (!args || !*args)
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
    New_Request (from->iface, 0,
		 "Lua: execute of your input returned %d results, first one is %s, string value of it is: %s.",
		 lua_gettop (Lua), lua_typename (Lua, lua_type (Lua, 1)),
		 lua_tostring (Lua, 1));
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
  char *c;
  INTERFACE *tmp;

  switch (sig)
  {
    case S_TERMINATE:
      Delete_Binding ("script", &script_lua, NULL);
      Delete_Binding ("register", &lua_register_variable, NULL);
      Delete_Binding ("function", &lua_register_function, NULL);
      Delete_Binding ("unregister", &lua_unregister_variable, NULL);
      Delete_Binding ("unfunction", &lua_unregister_function, NULL);
      Delete_Binding ("dcc", &dc_lua, NULL);
      l = NULL;
      while ((l = Next_Leaf (lua_bindtables, l, &c)))
	Delete_Binding (c, &binding_lua, NULL);	/* delete all bindings there */
      Destroy_Tree (&lua_bindtables, free);
      lua_close (Lua);
      Delete_Help ("lua");
      iface->ift |= I_DIED;
      break;
    case S_REG:
      Add_Request (I_INIT, "*", F_REPORT, "module lua");
      break;
    case S_REPORT:
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "Module lua: running.");
      Unset_Iface();
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
Function ModuleInit (char *args)
{
  ifsig_t sig = S_REG;

  CheckVersion;
  Lua = lua_open();
  luaL_openlibs (Lua);	/* open standard libraries */
  luaL_register (Lua, "foxeye", luatable_foxeye);
  luaL_register (Lua, "foxeye.client", luatable_foxeye_client);
  luaL_register (Lua, "net", luatable_net);
  lua_pop (Lua, 3);	/* remove three above from stack */
  lua_getglobal (Lua, "foxeye"); /* T */
  if (luaL_newmetatable (Lua, "fe_vars")) /* T m */
    // set all methods here
    luaL_register (Lua, NULL, luatable_vars); /* T m -- nothing to stack! */
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
  Add_Request (I_MODULE | I_INIT, "*", F_SIGNAL, (char *)&sig);
  Add_Help ("lua");
  return ((Function)&lua_module_signal);
}
#else	/* not HAVE_LIBLUA */
Function ModuleInit (char *args)
{
  ERROR ("Cannot run LUA, lualib not found, sorry.");
  return NULL;
}
#endif
