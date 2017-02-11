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
//remove all masks matched
		/* .class name [parameters] */
//either show, or change class parameters
		/* .bounce class [ip [port]] */
//either show, or change bounce address for class

/* -- common module interface --------------------------------------------- */
void ircd_management_proto_end (void)
{
  Delete_Binding ("dcc", &ss_ircd_phub, NULL);
}

void ircd_management_proto_start (void)
{
  Add_Binding ("ss-ircd", "+hub", U_MASTER, U_MASTER, &ss_ircd_phub, NULL);
  //Add_Binding ("ss-ircd", "-hub", U_MASTER, U_MASTER, &ss_ircd_phub, NULL);
  //Add_Binding ("ss-ircd", "class", U_MASTER, U_MASTER, &ss_ircd_phub, NULL);
  //Add_Binding ("ss-ircd", "bounce", U_MASTER, U_MASTER, &ss_ircd_phub, NULL);
}
#endif
