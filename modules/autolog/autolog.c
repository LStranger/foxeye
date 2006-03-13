/*
 * Copyright (C) 2006  Andrej N. Gritsenko <andrej@@rep.kiev.ua>
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
 * The FoxEye autolog module - auto creating log files for client traffic.
 *   TODO: "autolog by lname" feature.
 *   TODO: "U_SECRET" feature.
 */

#include "foxeye.h"
#include "modules.h"

#include "init.h"

static char autolog_ctl_prefix[32] = "-|- ";	/* prefix for notices */
static char autolog_path[128] = "~/.foxeye/logs/%@/%N";
static char autolog_open[64];			/* set on init */
static char autolog_close[64];
static char autolog_daychange[64];
static char autolog_timestamp[32] = "[%H:%M] ";	/* with ending space */
static bool autolog_by_lname = TRUE;
static long int autolog_autoclose = 600;	/* in seconds */

typedef struct autolog_t
{
  struct autolog_t *next;
  struct autolog_t *prev;
  char *path;
  int fd;
  time_t timestamp;
  int reccount;
  INTERFACE *iface;
  int inbuf;
  char buf[HUGE_STRING];
} autolog_t;

/* ----------------------------------------------------------------------------
 *	"*" autolog interface - handles new networks
 */
static iftype_t _autolog_mass_signal (INTERFACE *iface, ifsig_t sig)
{
}

static int _autolog_mass_request (INTERFACE *iface, REQUEST *req)
{
}


/* ----------------------------------------------------------------------------
 *	"@network" autolog interface - handles new logs
 */
static iftype_t _autolog_net_signal (INTERFACE *iface, ifsig_t sig)
{
}

static int _autolog_net_request (INTERFACE *iface, REQUEST *req)
{
}


/* ----------------------------------------------------------------------------
 *	"name@network" autolog interface - handles opened logs
 */
static iftype_t _autolog_name_signal (INTERFACE *iface, ifsig_t sig)
{
}

static int _autolog_name_request (INTERFACE *iface, REQUEST *req)
{
}


/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log.
 */
static int module_autolog_signal (INTERFACE *iface, ifsig_t sig)
{
    return 0;
}

/*
 * this function called when you load a module.
 * Input: parameters string args.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
Function ModuleInit (char *args)
{
  CheckVersion;
  strfcpy (autolog_open, _("IRC log started %c"), sizeof(autolog_open));
  strfcpy (autolog_close, _("IRC log ended %c"), sizeof(autolog_close));
  strfcpy (autolog_daychange, _("Day changed: %a %x"), sizeof(autolog_daychange));
  return NULL;
    //return (&module_autolog_signal);
}
