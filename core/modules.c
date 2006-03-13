/*
 * Copyright (C) 1999-2002  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file contains module control (load/unload/changing flags).
 */

#include "foxeye.h"

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include "modules.h"
#include "init.h"

#ifdef _OPENBSD
# undef RTLD_NOW
# define RTLD_NOW DL_LAZY
#endif

static bindtable_t *BT_Modadd = NULL;
static bindtable_t *BT_Moddel = NULL;

static char ModuleList[LONG_STRING];

static int scr_collect (INTERFACE *iface, REQUEST *req)
{
  if (req->from && req->from->name)
    strfcat (ModuleList, req->from->name, sizeof(ModuleList));
  return REQ_OK;
}

/* need for static compiling */
#define _MODULES_C 1
#include "modules.h"

ScriptFunction (FE_module)
{
  char cmd;
  char *c;
  char name[SHORT_STRING];
  INTERFACE *tmp;
  binding_t *bind = NULL;
  char sig[sizeof(ifsig_t)];
  Function func;
  iftype_t (*mods) (INTERFACE *, ifsig_t);
#ifndef STATIC
  char path[STRING];
  void *modh;
#else
  register int i;
#endif

  if (!args || !*args)				/* func must have parameters! */
    return 0;
  if (*args == '-')
  {
    if (args[1] == 'l')				/* get list of modules */
    {
      sig[0] = S_REPORT;
      tmp = Add_Iface (I_TEMP, NULL, NULL, &scr_collect, NULL);
      ModuleList[0] = 0;
      Set_Iface (tmp);
      ReportFormat = NULL;
      Add_Request (I_MODULE, "*", F_SIGNAL, sig);
      Unset_Iface();
      tmp->ift = I_DIED;
      BindResult = ModuleList;
      return 1;
    }
    cmd = args[1];
    args = NextWord (args);
  }
  else
    cmd = 'l';				/* load the module */
  /* find loaded module */
  strfcpy (name, args, sizeof(name));
  args = NextWord (args);
  for (c = name; *c && *c != ' '; c++);
  *c = 0;
  tmp = Find_Iface (I_MODULE, name);
  if (cmd == 'c')			/* check if module loaded */
  {
    if (tmp)
    {
      Unset_Iface();
      return 1;
    }
  }
  else if (cmd == 'd')			/* unload the module */
  {
    if (!tmp)					/* check if don't loaded */
      return 0;
    sig[0] = S_TERMINATE;
    New_Request (tmp, F_SIGNAL, sig);		/* kill the module */
#ifndef STATIC
    dlclose (tmp->data);			/* close dll */
#endif
    Unset_Iface();				/* unlock after Find_Iface() */
    if (!BT_Moddel)
      BT_Moddel = Add_Bindtable ("unload", B_MASK);
    do
    {
      if ((bind = Check_Bindtable (BT_Moddel, name, -1, -1, bind)))
      {
	if (bind->name)
	  RunBinding (bind, NULL, name, NULL, -1, NULL);
	else
	  bind->func (name);
      }
    } while (bind);
    Add_Request (I_LOG, "*", F_BOOT, "Unloaded module %s", name);
    return 1;
  }
  else if (cmd == 'l')			/* load the module */
  {
    /* check if already loaded */
    if (tmp)
    {
      Unset_Iface();
      return 0;
    }
    /* find module and startup function */
#ifndef STATIC
    snprintf (path, sizeof(path), MODULESDIR "/%s.so", name);
    modh = dlopen (path, RTLD_NOW);		/* force symbols resolving */
    if (modh == NULL)
      func = NULL;
    else
      func = (Function)dlsym (modh, "ModuleInit");
    if (!func)
    {
      c = (char *)dlerror();
      ERROR ("cannot load module %s: %s", name, NONULL(c));
      if (modh)
	dlclose (modh);
      return 0;
    }
#else
    for (i = 0; ModulesTable[i].name; i++)
      if (!safe_strcasecmp (ModulesTable[i].name, name))
	break;
    if ((func = (Function)ModulesTable[i].func) == NULL)
    {
      ERROR ("cannot start module %s: not found", name);
      return 0;
    }
#endif
    /* start the module */
    if ((mods = (iftype_t(*)(INTERFACE *,ifsig_t))func (args)) == NULL)
    {
      ERROR ("module %s: ModuleInit() error", name);
#ifndef STATIC
      dlclose (modh);
#endif
      return 0;
    }
#ifndef STATIC
    if (!Add_Iface (I_MODULE, name, mods, NULL, modh))
    {
      dlclose (modh);
#else
    if (!Add_Iface (I_MODULE, name, mods, NULL, NULL))
    {
#endif
      return 0;
    }
    if (!BT_Modadd)
      BT_Modadd = Add_Bindtable ("load", B_MASK);
    do
    {
      if ((bind = Check_Bindtable (BT_Modadd, name, -1, -1, bind)))
      {
	if (bind->name)
	  RunBinding (bind, NULL, name, NULL, -1, NULL);
	else
	  bind->func (name, args);
      }
    } while (bind);
    if (*args)
      Add_Request (I_LOG, "*", F_BOOT, "Loaded module %s (with args \"%s\")",
		   name, args);
    else
      Add_Request (I_LOG, "*", F_BOOT, "Loaded module %s", name);
    return 1;
  }
  else					/* unknown command? */
    ERROR ("invalid call: module -%c %s", cmd, args);
  return 0;
}
