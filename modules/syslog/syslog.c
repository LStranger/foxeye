/*
 * Copyright (C) 2016  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye project, module 'syslog'.
 */

#include "foxeye.h"
#include "modules.h"
#include "init.h"

#include <syslog.h>

static char syslog_facility[32] = "local0";
static char syslog_facility_old[32] = "";

static INTERFACE *_syslog = NULL;

#define SYSLOG_LEVELS \
    (F_USERS | F_CMDS | F_CONN | F_SERV | F_ERROR | F_WARN | F_DEBUG | F_BOOT)

static int _syslog_request(INTERFACE *iface, REQUEST *req)
{
  int prio;
  static const int locals[] = { LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3,
				LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7 };

  if (req && (req->flag & SYSLOG_LEVELS) && syslog_facility[0])
  {
    /* check if need to set facility */
    if (strcmp(syslog_facility, syslog_facility_old) != 0)
    {
      if (syslog_facility_old[0]) /* was opened before */
	closelog();
      strcpy(syslog_facility_old, syslog_facility);
      if (strncasecmp(syslog_facility, "local", 5) == 0)
	prio = locals[(atoi(&syslog_facility[5]) & 7)];
#ifdef LOG_DAEMON
      else if (strcasecmp(syslog_facility, "daemon") == 0)
	prio = LOG_DAEMON;
#endif
      else
	prio = LOG_USER;
      openlog(NULL, LOG_PID, prio);
    }
    if (req->flag & F_ERROR)
      prio = LOG_ERR;
    else if (req->flag & F_WARN)
      prio = LOG_WARNING;
    else if (req->flag & F_BOOT)
      prio = LOG_NOTICE;
    else if (req->flag == F_DEBUG)
      prio = LOG_DEBUG;
    else
      prio = LOG_INFO;
    syslog(prio, "%s", req->string);
  }
  return REQ_OK;
}

static iftype_t _syslog_signal(INTERFACE *iface, ifsig_t sig)
{
  switch (sig)
  {
    case S_TERMINATE:
      if (syslog_facility_old[0])
	closelog();
      syslog_facility_old[0] = 0;
      _syslog = NULL;
    case S_SHUTDOWN:
      return I_DIED;
    default: ;
  }
  return 0;
}

static void _syslog_register(void)
{
  /* register module itself */
  Add_Request(I_INIT, "*", F_REPORT, "module syslog");
  /* register all variables */
  RegisterString("syslog-facility", syslog_facility, sizeof(syslog_facility), 0);
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log,
 *  S_REG - report/register anything we should have in config file.
 */
static iftype_t module_signal(INTERFACE *iface, ifsig_t sig)
{
  switch (sig)
  {
    case S_TERMINATE:
      Delete_Help("syslog");
      if (_syslog)
	_syslog_signal(_syslog, sig);
      UnregisterVariable("syslog-facility");
      iface->ift |= I_DIED;
      break;
    case S_REG:
      /* reregister all */
      _syslog_register();
      break;
    case S_REPORT:
      if (_syslog)
      {
	INTERFACE *tmp = Set_Iface(iface);
	New_Request(tmp, F_REPORT, _("Module syslog: active."));
	Unset_Iface();
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
  Add_Help("syslog");
  _syslog_register();
  _syslog = Add_Iface(I_LOG, "*", &_syslog_signal, &_syslog_request, NULL);
  return (&module_signal);
}
