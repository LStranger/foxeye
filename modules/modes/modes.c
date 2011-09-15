/*
 * Copyright (C) 2010-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye module "modes".
 */

#include "foxeye.h"
#include "modules.h"
#include "init.h"
#include "list.h"
#include "direct.h"

static long int modes_default_ban_time = 172800;	/* default is 2d */

static char _modes_got[MESSAGEMAX];	/* buffer for hostmask */

static int _modes_receiver (INTERFACE *in, REQUEST *req)
{
  if (req)
    strfcpy (_modes_got, req->string, sizeof(_modes_got));
  return (REQ_OK);
}

static int _modes_bancmp (lid_t id, const char *mask, INTERFACE *tmp)
{
  _modes_got[0] = 0;			/* set it to empty */
  Get_Hostlist (tmp, id);
  Set_Iface (tmp);
  while (Get_Request());
  Unset_Iface();
  dprint (4, "modes:_modes_bancmp: check id %hd: got \"%s\".", id, _modes_got);
  return safe_strcmp (mask, _modes_got);
}

		/* .chban [%]mask service|* [+time] [reason] */
/* note for the side effect - if some nonamed excempt/invite/autoop/etc.
   already exists then it will be reverted to ban here! */
BINDING_TYPE_dcc (dc_chban);
static int dc_chban (struct peer_t *from, char *args)
{
  struct clrec_t *u;
  char *lname, *reason, *c, *tgt;
  lid_t id = ID_REM; /* shut up compiler */
  int sticky;
  time_t expire;
  INTERFACE *tmp;
  userflag uf;
  char mask[HOSTMASKLEN+1];

  /* check for parameters and find the mask in listfile */
  if (!(reason = safe_strchr (args, ' '))) /* two parameters at least */
    return 0;
  if (*args == '%')			/* if sticky mode requested */
  {
    args++;
    sticky = 1;
  }
  else
    sticky = 0;
  *reason = 0;
  unistrlower (mask, args, sizeof(mask)); /* get mask lowercase */
  *reason = ' ';
  args = NextWord (args);
  if (match ("*@*", mask) < 0)
    return 0;				/* need second parameter too */
  if ((u = Find_Clientrecord (mask, (const char **)&lname, &uf, NULL)) && lname)
  {
    Unlock_Clientrecord (u);		/* it's not unnamed ban! */
    u = NULL;
  }
  if (u)				/* release lock, we need only LID */
  {
    id = Get_LID (u);
    reason = safe_strdup (Get_Field (u, "info", NULL));
    Unlock_Clientrecord (u);
  }
  else
    reason = NULL;
  DBG ("modes:dc_chban:found id=%hd flags=%#x", id, uf);
  /* check if found record is exactly the unnamed mode */
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_modes_receiver, NULL);
  if (!u || _modes_bancmp (id, mask, tmp))
  {
    tmp->ift = I_DIED;
    FREE (&reason);
    New_Request (from->iface, 0, "There is no such ban: %s", mask);
    return 0;
  }
  /* check subfields and get old expiration time and reason */
  expire = Time + modes_default_ban_time;
  if (uf & U_DENY)			/* it's global ban now */
  {
    lname = "";
    u = Lock_byLID (id);
  }
  else					/* it's not global ban */
  {
    _modes_got[0] = 0;
    Get_Fieldlist (tmp, id);
    Set_Iface (tmp);
    while (Get_Request());
    Unset_Iface();
    tgt = c = NULL;			/* reset for later */
    u = NULL;
    for (lname = _modes_got; *lname; )	/* find a valid record */
    {
      c = gettoken (lname, &tgt);
      if (strrchr (lname, '@') == lname)
      {
	if ((u = Lock_Clientrecord (&lname[1])))
	  break;
      }
      else if ((u = Lock_Clientrecord (lname)))
	break;
      lname = c;
      if (*c)
	*tgt = ' ';			/* restore space now */
    }
    if (u)
    {
      Unlock_Clientrecord (u);
      u = Lock_byLID (id);
      uf = Get_Flags (u, lname);
      if (!(uf & U_DENY))		/* is it a ban at least? */
      {
	Unlock_Clientrecord (u);
	u = NULL;			/* not change ignores/etc with this */
      }
      DBG ("modes:dc_chban:tried %s, got flags %#x", lname, uf);
    }
    if (tgt && *c)			/* if we removed a space */
      *tgt = ' ';
    DBG ("modes:dc_chban: restored list=%s", _modes_got);
  }
  tmp->ift = I_DIED;			/* we don't need it anymore */
  if (!u)
  {
    FREE (&reason);
    New_Request (from->iface, 0, "There is no such ban: %s", mask);
    return 0;
  }
  c = Get_Field (u, lname, &expire);	/* get expiration time */
  Unlock_Clientrecord (u);
  /* OK, ban found, now check for new target(s) */
  args = NextWord_Unquoted (&mask[1], args, sizeof(mask)-1);
  if (!strcmp (&mask[1], "*"))		/* target is ALL, mark by empty */
    mask[0] = 0;
  else					/* checking Listfile for target(s) */
  {
    mask[0] = ' ';
    for (lname = tgt = &mask[1]; *lname; )
    {
      if ((c = strchr (lname, ',')))
	*c = 0;
      if ((u = Lock_Clientrecord (lname)))
      {
	uf = Get_Flags (u, NULL);
        Unlock_Clientrecord (u);
	DBG ("modes:dc_chban:valid target %s, flags %#x", lname, uf);
	if (uf & U_SPECIAL)		/* target can be only service name */
	{
	  if (lname != tgt)
	    memcpy (tgt, lname, strlen(lname));
	  tgt += strlen(lname);
	}
      }
      if (c)
      {
	if (tgt != &mask[1])		/* don't put space at beginning */
	  *tgt++ = ' ';			/* rewrite comma with space */
	lname = &c[1];			/* skip comma */
      }
      else
	break;
    }
    *tgt = 0;				/* terminate new list, just in case */
    if (mask[1] == 0)			/* no valid target found */
    {
      FREE (&reason);
      New_Request (from->iface, 0, "Invalid target list: %s", mask);
      return 0;
    }
  }
  /* since new target is OK, next we parse rest and update time/reason */
  if (*args == '+')			/* time description found */
  {
    long t = 0, tt;

    while (*args && *args != ' ')
    {
      args++;				/* skip last char */
      tt = strtol (args, &args, 10);
      if (*args == 'w')			/* weeks */
	t += tt * 3600 * 24 * 7;
      else if (*args == 'd')		/* days */
	t += tt * 3600 * 24;
      else if (*args == 'h')		/* hours */
	t += tt * 3600;
      else if (*args == 'm')		/* minutes */
	t += tt * 60;
    }
    if (t <= 0 || t > 3600 * 24 * 365)	/* validate it */
      t = modes_default_ban_time;
    expire = Time + t;
    args = NextWord (args);		/* it points on possible reason now */
  }
  /* removing any subfields we found */
  u = Lock_byLID (id);
  for (lname = _modes_got; *lname; )
  {
    c = gettoken (lname, NULL);
    if (strrchr (lname, '@') == lname)
      lname++;
    Set_Flags (u, lname, 0);
    lname = c;
  }
  /* update to new parameters */
  uf = U_DENY | (sticky ? U_NOAUTH : 0);
  Set_Field (u, "info", *args ? args : reason, 0);
  if (!*mask)				/* global ban */
  {
    Set_Field (u, "", "*", expire);	/* set it just to keep subrecord */
    Set_Flags (u, NULL, uf);		/* set global flags */
  }
  else
  {
    Set_Field (u, "", NULL, 0);		/* remove subfield if there is any */
    Set_Flags (u, NULL, 0);		/* reset global flags */
    for (lname = mask; lname; )
    {
      if ((tgt = strchr (&lname[1], ' ')))
	*tgt = 0;
      Set_Flags (u, &lname[1], uf);
      if (strchr (&lname[1], '@'))	/* channels */
	Set_Field (u, &lname[1], NULL, expire);
      else				/* networks */
      {
	*lname = '@';
	Set_Field (u, lname, NULL, expire);
      }
      *lname++ = ' ';
      lname = tgt;
    }
  }
  Unlock_Clientrecord (u);
  FREE (&reason);
  New_Request (from->iface, 0, "chban: updated to%s%s", mask,
	       sticky ? " (sticky)" : NULL);
  return 1;
}

		/* .+ban [%]mask service|* [+time] [reason] */
BINDING_TYPE_dcc (dc_pban);
static int dc_pban (struct peer_t *from, char *args)
{
  struct clrec_t *u;
  char *lname, *c, *tgt;
  lid_t id;
  int sticky;
  time_t expire;
  INTERFACE *tmp;
  userflag uf;
  unsigned char mask[HOSTMASKLEN+1];
  char target[MESSAGEMAX];

  /* check for parameters and validate mask */
  if (!(tgt = safe_strchr (args, ' '))) /* two parameters at least */
    return 0;
  if (*args == '%')			/* if sticky mode requested */
  {
    args++;
    sticky = 1;
  }
  else
    sticky = 0;
  *tgt = 0;
  unistrlower (mask, args, sizeof(mask)); /* get mask lowercase */
  *tgt = ' ';
  args = NextWord (tgt);		/* it's set to target(s) now */
  if (match ("*@*", mask) < 0)
    return 0;				/* need second parameter too */
  /* check if this mask does not exist as unnamed mode record yet */
  if ((u = Find_Clientrecord(mask, (const char **)&lname, NULL, NULL)) && lname)
  {
    Unlock_Clientrecord (u);		/* it's not unnamed ban! */
    u = NULL;
  }
  if (u)				/* release lock, we need only LID */
  {
    id = Get_LID (u);
    Unlock_Clientrecord (u);
    /* check if found record is exactly the unnamed mode */
    tmp = Add_Iface (I_TEMP, NULL, NULL, &_modes_receiver, NULL);
    if (u && !_modes_bancmp (id, mask, tmp))
    {
      tmp->ift = I_DIED;
      New_Request (from->iface, 0, "Cannot create a ban mask %s.", mask);
      return 0;
    }
    tmp->ift = I_DIED;			/* we don't need it anymore */
  }
  /* check target(s) now */
  args = NextWord_Unquoted (&target[1], args, sizeof(target)-1);
  if (!strcmp (&target[1], "*"))	/* target is ALL, mark by empty */
    target[0] = 0;
  else					/* checking Listfile for target(s) */
  {
    target[0] = ' ';
    for (lname = tgt = &target[1]; *lname; )
    {
      if ((c = strchr (lname, ',')))
	*c = 0;
      if ((u = Lock_Clientrecord (lname)))
      {
	uf = Get_Flags (u, NULL);
        Unlock_Clientrecord (u);
	DBG ("modes:dc_pban:valid target %s, flags %#x", lname, uf);
	if (uf & U_SPECIAL)		/* target can be only service name */
	{
	  if (lname != tgt)
	    memcpy (tgt, lname, strlen(lname));
	  tgt += strlen(lname);
	}
      }
      else
	DBG ("modes:dc_pban:invalid target %s", lname);
      if (c)
      {
	if (tgt != &target[1])		/* don't put space at beginning */
	  *tgt++ = ' ';			/* rewrite comma with space */
	lname = &c[1];			/* skip comma */
      }
      else
	break;
    }
    if (tgt == &target[1])		/* no valid target found */
    {
      New_Request (from->iface, 0, "Invalid target list: %s", target);
      return 0;
    }
    *tgt = 0;				/* terminate new list, just in case */
  }
  /* since new target is OK, next we parse rest and update time/reason */
  if (*args == '+')			/* time description found */
  {
    long t = 0, tt;

    while (*args && *args != ' ')
    {
      args++;				/* skip last char */
      tt = strtol (args, &args, 10);
      if (*args == 'w')			/* weeks */
	t += tt * 3600 * 24 * 7;
      else if (*args == 'd')		/* days */
	t += tt * 3600 * 24;
      else if (*args == 'h')		/* hours */
	t += tt * 3600;
      else if (*args == 'm')		/* minutes */
	t += tt * 60;
    }
    if (t <= 0 || t > 3600 * 24 * 365)	/* validate it */
      t = modes_default_ban_time;
    expire = Time + t;
    args = NextWord (args);		/* it points on possible reason now */
  }
  else
    expire = Time + modes_default_ban_time;
  /* target(s) are OK so it's time to add new record */
  if (!Add_Clientrecord (NULL, mask, 0)) /* nothing is set for now */
  {
    ERROR ("modes:dc_pban: unexpected error, could not add %s!", mask);
    return -1;
  }
  u = Find_Clientrecord (mask, (const char **)&tgt, NULL, NULL);
  if (!u || tgt != NULL)
  {
    ERROR ("modes:dc_pban: unexpected error!");
    Unlock_Clientrecord (u);
    return -1;				/* it should never happen! */
  }
  uf = U_DENY | (sticky ? U_NOAUTH : 0);
  if (*args)
    Set_Field (u, "info", args, 0);	/* call only if reason was set */
  if (!*target)				/* global ban */
  {
    Set_Flags (u, NULL, uf);		/* set global flags */
    Set_Field (u, "", "*", expire);	/* set it just to keep subrecord */
  }
  else
  {
    for (lname = target; lname; )
    {
      if ((tgt = strchr (&lname[1], ' ')))
	*tgt = 0;
      Set_Flags (u, &lname[1], uf);
      if (strchr (&lname[1], '@'))	/* channels */
	Set_Field (u, &lname[1], NULL, expire);
      else				/* networks */
      {
	*lname = '@';
	Set_Field (u, lname, NULL, expire);
      }
      *lname++ = ' ';
      lname = tgt;
    }
  }
  Unlock_Clientrecord (u);
  New_Request (from->iface, 0, "+ban: added%s%s", mask,
	       sticky ? " (sticky)" : NULL);
  return 1;
}

		/* .-ban mask */
BINDING_TYPE_dcc (dc_mban);
static int dc_mban (struct peer_t *from, char *args)
{
  struct clrec_t *u;
  const char *lname;
  lid_t id = ID_REM; /* shut up compiler */
  INTERFACE *tmp;

  /* check if parameter is mask really */
  if (match ("*@*", args) < 0)
    return 0;				/* need second parameter too */
  /* check if there is such unnamed mode exist in Listfile */
  if ((u = Find_Clientrecord (args, &lname, NULL, NULL)) && lname)
  {
    Unlock_Clientrecord (u);		/* it's not unnamed ban! */
    DBG ("modes:dc_mban:found lname %s instead of ban", lname);
    u = NULL;
  }
  if (u)				/* release lock, we need only LID */
  {
    id = Get_LID (u);
    Unlock_Clientrecord (u);
  }
  else
    DBG ("modes:dc_mban:mask %s wasn't found", args);
  /* check if found record is exactly the unnamed mode */
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_modes_receiver, NULL);
  if (!u || _modes_bancmp (id, args, tmp))
  {
    tmp->ift = I_DIED;
    New_Request (from->iface, 0, "There is no such ban: %s", args);
    return 0;
  }
  tmp->ift = I_DIED;			/* we don't need it anymore */
  /* remove mask from it and record will be deleted on next save */
  u = Lock_byLID (id);
  if (Delete_Mask (u, "*@*"))		/* clear every host ;) */
    id = id;				/* and ignore result */
  Unlock_Clientrecord (u);
  return 1;
}

		/* .comment lname [text] */
BINDING_TYPE_dcc (dc_comment);
static int dc_comment (struct peer_t *who, char *args)
{
  char *c, *r;
  struct clrec_t *u;

  if (!args)
    return 0;				/* need at least 1 arg */
  r = gettoken (args, &c);
  u = Lock_Clientrecord (args);
  if (!u)
  {
    New_Request (who->iface, 0, "Name %s not found", args);
    if (*r)
      *c = ' ';
    return 0;
  }
  args = Get_Field (u, NULL, NULL);	/* unalias the name */
  if (*r)
  {
    Set_Field (u, "info", r, 0);
    Unlock_Clientrecord (u);
    New_Request (who->iface, 0, "Info on %s set to \"%s\".", args, r);
    *c = ' ';
  }
  else
  {
    r = safe_strdup (Get_Field (u, "info", NULL));
    Unlock_Clientrecord (u);
    if (r)
    {
      New_Request (who->iface, 0, "Info on %s is \"%s\".", args, r);
      FREE (&r);
    }
    else
      New_Request (who->iface, 0, "No info is set on %s.", args);
  }
  return 1;
}

		/* .greeting [service[@net]] [--lname] [text|"NONE"] */
BINDING_TYPE_dcc (dc_greeting);
static int dc_greeting (struct peer_t *who, char *args)
{
  char sname[IFNAMEMAX+1];	/* for sname + netname */
#if IFNAMEMAX < 127
  char buf[128];		/* for default service or Lname */
#else
  char buf[IFNAMEMAX+1];
#endif
  char *netname, *tgt;
  struct clrec_t *u;
  userflag uf, tf;

  if (!args)
    args = "";				/* assuming empty input */
  /* check target service now or get it from default */
  if (strchr (CHANNFIRSTCHAR, args[0]))	/* we got service name in command */
    args = NextWord_Unquoted (sname, args, sizeof(sname));
  else
    sname[0] = 0;
  netname = strrchr (sname, '@');
  if (!netname)
  {
    if (!(u = Lock_Clientrecord (who->iface->name)))
    {
      ERROR ("modes:dc_greeting: unknown error with Lname %s", who->iface->name);
      return -1;				/* oops, nothing to report */
    }
    tgt = Get_Field (u, "", NULL);		/* use tgt as temp pointer */
    if (!tgt || !sscanf (tgt, "%*s %127s %*s", buf))
      buf[0] = 0;				/* cannot determine it... */
    Unlock_Clientrecord (u);
    if (!sname[0])				/* take chan@net from cons */
      strfcpy (sname, buf, sizeof(sname));
    else if ((netname = strrchr (buf, '@')))	/* add @net to given chan */
      strfcat (sname, netname, sizeof(sname));
    netname = strrchr (sname, '@');		/* trying to determine net */
    if (!netname)
      return 0;					/* it's syntax error for sure */
  }
  if ((u = Lock_Clientrecord (sname)))
    Unlock_Clientrecord (u);
  else
  {
    New_Request (who->iface, 0, _("No such active service: %s"), sname);
    return 0;					/* it's syntax error :) */
  }
  netname++;					/* skipping '@' now */
  /* check if we are trying to change someone's greeting */
  if (args[0] == '-' && args[1] == '-')
  {
    DBG ("modes:dc_greeting: check perm: %s@%s/%s", who->iface->name, netname, sname);
    uf = (Get_Clientflags (who->iface->name, NULL) |	/* global */
	  Get_Clientflags (who->iface->name, netname) |	/* network */
	  Get_Clientflags (who->iface->name, sname));	/* channel */
    if (uf & U_MASTER)
    {
      args = NextWord_Unquoted (buf, &args[2], sizeof(buf));
      u = Lock_Clientrecord (buf);
      if (!u)				/* Lname does not exist */
      {
	New_Request (who->iface, 0, _("No such client name: %s"), buf);
	return 0;
      }
      tf = (Get_Flags (u, NULL) | Get_Flags (u, netname) | Get_Flags (u, sname));
      Unlock_Clientrecord (u);
      /* master may see/change only own or not-masters greeting */
      if ((tf & (U_MASTER | U_OWNER)) && !(uf & U_OWNER) &&
	  safe_strcasecmp (buf, who->iface->name))
      {
	New_Request (who->iface, 0, _("Permission denied."));
	return 0;
      }
      tgt = buf;
    }
    else
    {
      args = NextWord (args);		/* if not permitted then just skip */
      tgt = who->iface->name;
    }
  }
  else
    tgt = who->iface->name;
  if (!*args)
  {
    char *c;

    u = Lock_Clientrecord (tgt);
    if (u)
    {
      c = safe_strdup (Get_Field (u, sname, NULL));
      Unlock_Clientrecord (u);
    }
    else				/* hmm, how it may be? */
      c = NULL;
    if (c == NULL)
      New_Request (who->iface, 0, _("No greeting is set on %s for %s."), sname,
		   tgt);
    else
      New_Request (who->iface, 0, _("Greeting on %s for %s is: %s"), sname,
		   tgt, c);
    FREE (&c);
    return 1;
  }
  if (!strcmp (args, "NONE"))
  {
    u = Lock_Clientrecord (tgt);
    if (u)
    {
      Set_Field (u, sname, NULL, 0);
      Unlock_Clientrecord (u);
      New_Request (who->iface, 0, _("Greeting on %s for %s reset."), sname,
		   tgt);
    }
    else
      WARNING ("modes:dc_greeting: unknown error with Lname %s", tgt);
    return 1;
  }
  u = Lock_Clientrecord (tgt);
  if (!u)
  {
    WARNING ("modes:dc_greeting: unknown error with Lname %s", tgt);
    return -1;
  }
  Set_Field (u, sname, args, 0);
  Unlock_Clientrecord (u);
  New_Request (who->iface, 0, _("Greeting on %s for %s set to: %s"), sname,
	       tgt, args);
  return 1;
}


/*
 * this function receives signals:
 *  S_REG - register everything,
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log.
 */
static iftype_t module_signal (INTERFACE *iface, ifsig_t sig)
{
  INTERFACE *tmp;

  if (sig == S_REG)
  {
    Add_Request (I_INIT, "*", F_REPORT, "module modes");
    RegisterInteger ("default-ban-time", &modes_default_ban_time);
  }
  else if (sig == S_REPORT)
  {
    tmp = Set_Iface (iface);
    New_Request (tmp, F_REPORT, "Module modes: working.");
    Unset_Iface();
  }
  else if (sig == S_TERMINATE)
  {
    Delete_Help ("modes");
    Delete_Binding ("dcc", &dc_greeting, NULL);
    Delete_Binding ("dcc", &dc_pban, NULL);
    Delete_Binding ("dcc", &dc_mban, NULL);
    Delete_Binding ("dcc", &dc_chban, NULL);
    Delete_Binding ("dcc", &dc_comment, NULL);
    UnregisterVariable ("default-ban-time");
    return (I_DIED);
  }
  return 0;
}

/*
 * this function called when you load a module.
 * Input: parameters string args, no parameters currently.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
SigFunction ModuleInit (char *args)
{
  CheckVersion;
  Add_Help ("modes");
  Add_Binding ("dcc", "greeting", 0, 0, &dc_greeting, NULL);
  Add_Binding ("dcc", "+ban", U_OP, U_OP, &dc_pban, NULL);
  Add_Binding ("dcc", "-ban", U_OP, U_OP, &dc_mban, NULL);
  Add_Binding ("dcc", "chban", U_OP, U_OP, &dc_chban, NULL);
  Add_Binding ("dcc", "comment", U_OP, U_OP, &dc_comment, NULL);
  RegisterInteger ("default-ban-time", &modes_default_ban_time);
  return (&module_signal);
}
