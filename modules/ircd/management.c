/*
 * Copyright (C) 2017  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye IRCd module: management bindings.
 *
 * TODO: make support for script bindings!
 */

#include "foxeye.h"
#if IRCD_USES_ICONV == 0 || (defined(HAVE_ICONV) && (IRCD_NEEDS_TRANSLIT == 0 || defined(HAVE_CYRILLIC_TRANSLIT)))
#include "modules.h"
#include "direct.h"
#include "list.h"

/* -- command line interface ---------------------------------------------- */
		/* .+hub server mask */
BINDING_TYPE_ss_ (ss_ircd_phub);
static int ss_ircd_phub (struct peer_t *dcc, INTERFACE *srv, char *args)
{
  char *c, *r;
  struct clrec_t *u;
  int ret;

  if (!args)
    return 0;				/* need exactly 2 args */
  r = gettoken (args, &c);
  if (!*r)
    return 0;				/* need exactly 2 args */
  u = Lock_Clientrecord (args);
  if (!u)
  {
    New_Request (dcc->iface, 0, "Server %s not found", args);
    if (*r)
      *c = ' ';
    return 0;
  }
  args = safe_strdup(Get_Field(u, NULL, NULL)); /* unalias the name */
  ret = Grow_Field (u, "hub", r);
  Unlock_Clientrecord (u);
  if (ret)
    New_Request (dcc->iface, 0, "Added hub mask \"%s\" for %s.", r, args);
  else
    New_Request (dcc->iface, 0, "Failed to add hub mask \"%s\" for %s.", r, args);
  FREE(&args);
  *c = ' ';
  return 1;
}

		/* .-hub server mask */
BINDING_TYPE_ss_ (ss_ircd_mhub);
static int ss_ircd_mhub (struct peer_t *dcc, INTERFACE *srv, char *args)
{
  char *c, *r , *f, *ff, *fn, *fc, *fp;
  struct clrec_t *u;
  int ret = 1;

  if (!args)
    return 0;				/* need exactly 2 args */
  r = gettoken (args, &c);
  if (!*r)
    return 0;				/* need exactly 2 args */
  u = Lock_Clientrecord (args);
  if (!u)
  {
    New_Request (dcc->iface, 0, "Server %s not found", args);
    if (*r)
      *c = ' ';
    return 0;
  }
  args = safe_strdup(Get_Field(u, NULL, NULL)); /* unalias the name */
  for (ff = fp = f = safe_strdup(Get_Field(u, "hub", NULL)); f && *f; )
  {
    fn = gettoken(f, &fc);
    while (match(r, f) > 0)
    {
      DBG("ircd:-hub: %s matches %s, skipping it", f, r);
      f = fn;
      if (*f == '\0')
	break;
      fn = gettoken(f, NULL);
    }
    if (*f)
    {
      DBG("ircd:-hub: keeping %s", f);
      if (fp != ff)
	*fp++ = ' ';
      if (f != fp)
	memmove(fp, f, strlen(f));
      fp += strlen(f);
      f = fn;
    }
  }
  if (fp)
    *fp = '\0';
  if (ff)
    ret = Set_Field(u, "hub", ff, 0);
  Unlock_Clientrecord (u);
  FREE(&ff);
  if (ret)
    New_Request (dcc->iface, 0, "Removed hub mask \"%s\" from %s.", r, args);
  else
    New_Request (dcc->iface, 0, "Failed to remove hub mask \"%s\" from %s.", r, args);
  FREE(&args);
  *c = ' ';
  return 1;
}

		/* .class name [parameters] */
BINDING_TYPE_ss_ (ss_ircd_class);
static int ss_ircd_class (struct peer_t *dcc, INTERFACE *srv, char *args)
{
  char *c, *p;
  struct clrec_t *u;
  char n[NAMEMAX+2];
  userflag uf;

  if (!args)		/* needs at least 1 param */
    return 0;
  if (!srv || !srv->name)
  {
    New_Request(dcc->iface, 0, "Fatal: no ircd server is running");
    return -1;
  }
  p = gettoken(args, &c);
  u = Lock_Clientrecord (args);
  if (!u)
  {
    New_Request(dcc->iface, 0, "Class %s not found", args);
    if (*p)
      *c = ' ';
    return 0;
  }
  uf = Get_Flags(u, srv->name);
  if (uf & (U_UNSHARED | U_SPEAK)) /* server or service */
  {
    New_Request(dcc->iface, 0, "The name %s is not a class", args);
    Unlock_Clientrecord(u);
    if (*p)
      *c = ' ';
    return 0;
  }
  args = safe_strdup(Get_Field(u, NULL, NULL)); /* unalias the name */
  snprintf(n, sizeof(n), "@%s", srv->name);
  if (!*p)		/* just a query */
  {
    p = Get_Field(u, n, NULL);
    New_Request(dcc->iface, 0, "Class %s: u/l u/g u/c pf sq: %s", args,
		p ? p : "defaults");
  }
  else			/* setting a param */
  {
    //FIXME: do validations?
    if (Set_Field(u, n, p, 0) == 0)
      New_Request(dcc->iface, 0, "Failed to update class %s settings", args);
    else
      New_Request(dcc->iface, 0, "Class %s: u/l u/g u/c pf sq: %s", args, p);
  }
  Unlock_Clientrecord(u);
  FREE(&args);
  if (*p)
    *c = ' ';
  return 1;
}

		/* .bounce class [ip [port]] */
//either show, or change bounce address for class
		/* .history server */
//show last 10 connects of chosen server

/* -- common module interface --------------------------------------------- */
void ircd_management_proto_end (void)
{
  Delete_Binding ("ss-ircd", &ss_ircd_phub, NULL);
  Delete_Binding ("ss-ircd", &ss_ircd_mhub, NULL);
  Delete_Binding ("ss-ircd", &ss_ircd_class, NULL);
}

void ircd_management_proto_start (void)
{
  Add_Binding ("ss-ircd", "+hub", U_MASTER, U_MASTER, &ss_ircd_phub, NULL);
  Add_Binding ("ss-ircd", "-hub", U_MASTER, U_MASTER, &ss_ircd_mhub, NULL);
  Add_Binding ("ss-ircd", "class", U_MASTER, U_MASTER, &ss_ircd_class, NULL);
  //Add_Binding ("ss-ircd", "bounce", U_OP, U_OP, &ss_ircd_bounce, NULL);
  //Add_Binding ("ss-ircd", "history", U_OP, U_HALFOP, &ss_ircd_history, NULL);
}
#endif
