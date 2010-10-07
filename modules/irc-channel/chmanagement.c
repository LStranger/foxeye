/*
 * Copyright (C) 2005-2010  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * FoxEye's "irc-channel" module. Channel management: parsing and setting all
 *   modes on the channel, "ss-irc" bindings.
 *   
 */

#include "foxeye.h"

#include <ctype.h>

#include "tree.h"
#include "wtmp.h"
#include "init.h"
#include "sheduler.h"
#include "direct.h"
#include "irc-channel.h"

extern long int ircch_enforcer_time;		/* from irc-channel.c */
extern bool ircch_ignore_ident_prefix;
extern long int ircch_ban_keep;
//extern long int ircch_exempt_keep;
//extern long int ircch_invite_keep;
extern long int ircch_mode_timeout;
extern char ircch_default_kick_reason[];

#define	MODECHARSMAX	32	/* long int capable */
#define	MODECHARSFIX	2	/* channel's specials, see IRC structure */

typedef struct
{
  uchar mc[MODECHARSMAX];	/* chars of modes */
  uchar mcf[MODECHARSFIX];	/* references to above for specials */
  uchar admin, anonymous, halfop;
} m_c;

typedef struct
{
  int changes;
  size_t pos, apos;
  const char *cmd;
  char modechars[MODECHARSMAX];
  char mchg[STRING];
  char args[STRING];
} modebuf;

static m_c *ModeChars = NULL;

/* TODO: extra channel modes:
    Rizon: MNOZ
    irchighway: AKMNOS
    ChatSpike: a,fruzACGKL,MNOQSTV */

static void _make_modechars (char *modechars, IRC *net)
{
  unsigned long int i, m;

  if (!ModeChars)
  {
    ModeChars = safe_calloc (1, sizeof(m_c));
    for (i = 0; i < MODECHARSFIX; i++)
      ModeChars->mcf[i] = MODECHARSMAX;
    for (m = 1, i = 0; i < MODECHARSMAX && m; m += m, i++)
    {
      /* fill network specific values */
      if (m == A_RESTRICTED)
	ModeChars->mcf[0] = i;
      else if (m == A_REGISTERED)
	ModeChars->mcf[1] = i;
      else if (m == A_ADMIN)	/* first reserved is admin status 'a' */
	ModeChars->admin = i;
      else if (m == A_ANONYMOUS)/* second reserved is anonymous 'a' */
	ModeChars->anonymous = i;
      else if (m == A_HALFOP)	/* third reserved is halfop 'h' */
	ModeChars->halfop = i;
      /* and standard ones */
      else if (m == A_OP)
	ModeChars->mc[i] = 'o';
      else if (m == A_VOICE)
	ModeChars->mc[i] = 'v';
      else if (m == A_DENIED)
	ModeChars->mc[i] = 'b';
      else if (m == A_INVITED)
	ModeChars->mc[i] = 'I';
      else if (m == A_EXEMPT)
	ModeChars->mc[i] = 'e';
      else if (m == A_INVITEONLY)
	ModeChars->mc[i] = 'i';
      else if (m == A_MODERATED)
	ModeChars->mc[i] = 'm';
      else if (m == A_QUIET)
	ModeChars->mc[i] = 'q';
      else if (m == A_NOOUTSIDE)
	ModeChars->mc[i] = 'n';
      else if (m == A_PRIVATE)
	ModeChars->mc[i] = 'p';
      else if (m == A_SECRET)
	ModeChars->mc[i] = 's';
      else if (m == A_REOP)
	ModeChars->mc[i] = 'r';
      else if (m == A_TOPICLOCK)
	ModeChars->mc[i] = 't';
      else if (m == A_NOCOLOR)
	ModeChars->mc[i] = 'c';
      else if (m == A_ASCIINICK)
	ModeChars->mc[i] = 'z';
    }
  }
  memcpy (modechars, &ModeChars->mc, MODECHARSMAX);
  if (net->features & L_HASADMIN)
    modechars[ModeChars->admin] = 'a';		/* admin */
  else
  {
    modechars[ModeChars->admin] = 'O';		/* creator */
    modechars[ModeChars->anonymous] = 'a';	/* anonymous */
  }
  if (net->features & L_HASHALFOP)
    modechars[ModeChars->halfop] = 'h';		/* halfop */
  for (i = 0; i < MODECHARSFIX; i++)
    if (ModeChars->mcf[i] < MODECHARSMAX)
      modechars[ModeChars->mcf[i]] = net->modechars[i];
}

static LINK *_find_me_op (IRC *net, CHANNEL *ch)
{
  LINK *me;

  if (!ch)
    return NULL;
  for (me = net->me->channels; me; me = me->prevchan)
    if (me->chan == ch)
      break;
  if (me && !(me->mode & (A_ADMIN | A_OP | A_HALFOP)))
    return NULL;
  return me;
}

/* sf is global (G) plus server (S) flags, cf is channel (C) flags
   (S) are U_DENY,U_ACCESS,U_OP,U_HALFOP,U_AUTO,U_DEOP, all other are (G) */
static userflag _make_rf (IRC *net, const userflag sf, const userflag cf)
{
  userflag rf, tf;

  rf = cf & (U_DENY | U_ACCESS);		/* channel access group prior */
  if (!rf)
    rf = sf & (U_DENY | U_ACCESS);
  rf |= (cf | sf) & (U_FRIEND | U_OWNER | U_SPECIAL | U_IGNORED); /* just OR these */
  if (!(net->features & L_HASADMIN))
  {
    tf = U_HALFOP | U_OP | U_DEOP;
    rf |= (cf | sf) & U_MASTER;
  }
  else
    tf = U_MASTER | U_HALFOP | U_OP | U_DEOP;
  if (cf & (U_QUIET | U_VOICE | U_SPEAK))	/* channel voice group prior */
    rf |= cf & (U_QUIET | U_VOICE | U_SPEAK);
  else
    rf |= sf & (U_QUIET | U_VOICE);
  if (cf & tf)					/* channel op group prior */
    rf |= cf & (tf | U_AUTO);
  else
    rf |= sf & (tf | U_AUTO);
  DBG ("irc-channel:chmanagement.c:_make_rf: 0x%08x:0x%08x=>0x%08x", sf, cf, rf);
  return rf;
}

static char *_make_mask (char *mask, char *uh, size_t s)
{
  register char *c, *m;
  int n;

  if (s < 9) return NULL;	/* it cannot be true, at least "*!*@*.xx\0" */
  m = mask;
  n = 0;
  for (c = uh; *c && *c != '!'; c++);
  *m++ = '*';
  if (ircch_ignore_ident_prefix == TRUE && *c == '!' && strchr ("^~-=+", c[1]))
  {
    *m++ = '!';
    *m++ = '?';
    c += 2;
  }
  while (m < &mask[s-3] && *c)
  {
    if (*c == '[' || *c == '{' || *c == '*')	/* mask all match() chars */
      *m++ = '?';
    else
      *m++ = *c;
    if (*c++ == '@')
      break;
  }
  uh = c;
  while (*c) c++;
  while (c > uh)
  {
    if (*(--c) == '.' && (++n) == 3)		/* third dot reached, stop */
      break;
    if (*c >= '0' && *c <= '9' && n != 1)	/* in 2nd domain ignore it */
      break;
  }
  if (n == 0)					/* numeric host? */
  {
    c = uh;
    while (m < &mask[s-3] && *c && n < 3)
    {
      *m++ = *c++;
      if (*c == '.')
	n++;
    }
    *m++ = '.';
    *m++ = '*';
  }
  else if (c != uh || n > 1)			/* some numerics found */
  {
    *m++ = '*';
    *m++ = '.';
    while (*c && *c != '.')
      c++;
    if (*c)
      c++;
    while (m < &mask[s-1] && *c)
      *m++ = *c++;
  }
  else						/* domain 1st or 2nd level */
  {
    while (m < &mask[s-1] && *c)
      *m++ = *c++;
  }
  *m = 0;
  return mask;
}

static char *_make_literal_mask (char *mask, char *uh, size_t s)
{
  register char *c, *m;

  if (s < 9) return NULL;	/* it cannot be true, at least "*!*@*.xx\0" */
  m = mask;
  for (c = uh; *c && *c != '!'; c++);
  *m++ = '*';
  if (ircch_ignore_ident_prefix == TRUE && *c == '!' && strchr ("^~-=+", c[1]))
  {
    *m++ = '!';
    *m++ = '?';
    c += 2;
  }
  while (m < &mask[s-1] && *c)
  {
    if (*c == '[' || *c == '{' || *c == '*')	/* mask all match() chars */
      *m++ = '?';
    else
      *m++ = *c;
    c++;
  }
  *m = 0;
  return mask;
}

static void _flush_mode (IRC *net, CHANNEL *chan, modebuf *mbuf)
{
  char *c;
  size_t s;

  if (mbuf->cmd == NULL || mbuf->changes == 0)
    return;
  c = strrchr (chan->chi->name, '@');
  if (c) s = c - (char *)chan->chi->name;
  else s = strlen (chan->chi->name);
  mbuf->mchg[mbuf->pos] = 0;
  mbuf->args[mbuf->apos] = 0;
  DBG("_flush_mode:%s %.*s %s %s", mbuf->cmd, s, chan->chi->name, mbuf->mchg, mbuf->args);
  New_Request (net->neti, 0, "%s %.*s %s %s", mbuf->cmd, s, chan->chi->name,
	       mbuf->mchg, mbuf->args);
  mbuf->cmd = NULL;
  mbuf->changes = mbuf->pos = mbuf->apos = 0;
}

static void _push_mode (IRC *net, LINK *target, modebuf *mbuf,
			modeflag mch, int add, char *mask)
{
  char *CMD_MODE = "MODE";
  size_t i, m;

  if (!_find_me_op (net, target->chan))
    return; /* I'm not op there */
  for (m = 0; m < MODECHARSMAX && !(mch & (1<<m)); m++);
  if (m == MODECHARSMAX || mbuf->modechars[m] == 0)
    return; /* oops, illegal mode! */
  if (mbuf->cmd != CMD_MODE || mbuf->changes == net->maxmodes)
  {
    _flush_mode (net, target->chan, mbuf);
    mbuf->cmd = CMD_MODE;
  }
  /* check for user-on-chan mode changes */
  if (mch & (A_ADMIN | A_OP | A_HALFOP | A_VOICE))
  {
    register char *c;

    mask = target->nick->host;
    i = safe_strlen (mask);
    c = memchr (mask, '!', i);
    if (c)
      i = c - mask;
  }
  else
    i = safe_strlen (mask);
  /* check if we need flush */
  if (mbuf->apos && mbuf->apos + i >= sizeof(mbuf->args) - 2)
    _flush_mode (net, target->chan, mbuf);
  if (mbuf->pos && ((add && *mbuf->mchg == '-') || (!add && *mbuf->mchg == '+')))
    _flush_mode (net, target->chan, mbuf);
  /* add change to mbuf */
  if (!mbuf->changes)
  {
    if (add)
      *mbuf->mchg = '+';
    else
      *mbuf->mchg = '-';
    mbuf->pos++;
  }
  mbuf->mchg[mbuf->pos++] = mbuf->modechars[m];
  mbuf->changes++;
  target->lmct = Time;
  if (!i)
    return;
  if (i >= sizeof(mbuf->args) - mbuf->apos) /* it's impossible but anyway */
    i = sizeof(mbuf->args) - mbuf->apos - 1;
  if (mbuf->apos)
    mbuf->args[mbuf->apos++] = ' ';
  memcpy (&mbuf->args[mbuf->apos], mask, i);
  mbuf->apos += i;
}

static void _push_listfile_mode (IRC *net, LINK *target, modebuf *mbuf,
				 modeflag mch, int add, char *mask)
{
  char str[HOSTMASKLEN+1];
  char *c, *cc;
  int i = 0;

  /* convert pattern to RFC2812 one */
  for (c = mask, cc = str; *c && cc < &str[HOSTMASKLEN]; )
  {
    if (*c == '[')
    {
      *cc++ = '?';
      if (*++c == ']')			/* it might be first char */
	c++;
      while (*c && *c++ != ']');	/* skip rest of subpattern */
    }
    else if (*c == '{')
    {
      *cc++ = '*';
      FOREVER
      {
	if (*c == '{')			/* + recursion level */
	  i++;
	else if (*c == '[')		/* skip whole subpattern */
	{
	  if (*++c == ']')
	    c++;
	  while (*c && *c++ != ']');
	}
	else if (*c == '\\' && *++c)	/* skip escaped char */
	  c++;
	if (*c++ == '}' && --i == 0)	/* - recursion level */
	  break;
	if (*c == 0)
	  break;
      }
    }
    else
      *cc++ = *c++;
  }
  *cc = 0;
  _push_mode (net, target, mbuf, mch, add, str);
}

static void _push_kick (IRC *net, LINK *target, modebuf *mbuf,
		        char *reason)
{
  char *CMD_KICK = "KICK";
  char *c;
  size_t i, m;

  if (!_find_me_op (net, target->chan))
    return; /* I'm not op there */
  if (mbuf->cmd != CMD_KICK || mbuf->changes == net->maxtargets)
  {
    _flush_mode (net, target->chan, mbuf);
    mbuf->cmd = CMD_KICK;
  }
  m = safe_strlen (target->nick->host);
  c = memchr (target->nick->host, '!', m);
  if (c)
    m = c - target->nick->host;
  if (mbuf->pos && mbuf->pos + m >= sizeof(mbuf->args) - 2)
    _flush_mode (net, target->chan, mbuf);
  i = safe_strlen (reason);
  if (i >= sizeof(mbuf->args) - 1)
    i = sizeof(mbuf->args) - 2;
  if (mbuf->apos && (i != mbuf->apos - 1 ||
      safe_strncmp (&mbuf->args[1], reason, mbuf->apos - 1)))
    _flush_mode (net, target->chan, mbuf);
  if (!mbuf->apos && i != 0) /* write reason */
  {
    *mbuf->args = ':';
    memcpy (&mbuf->args[1], reason, i);
    mbuf->apos = i + 1;
  }
  if (mbuf->pos)
    mbuf->mchg[mbuf->pos++] = ',';
  memcpy (&mbuf->mchg[mbuf->pos], target->nick->host, m);
  mbuf->pos += m;
  mbuf->changes++;
}

typedef struct
{
  IRC *net;
  CHANNEL *chan;
  modebuf *mbuf;
  char *type;
  modeflag mf;
  char *banmask;
  lid_t id;
} _ircch_list_raise_struct;

static int _ircch_list_raise_receiver (INTERFACE *iface, REQUEST *req)
{
  _ircch_list_raise_struct *s = iface->data;
  char *c, *next;

  if (req && *(c = req->string)) do
  {
    next = gettoken (c, NULL);
    if (s->id != ID_REM)			/* we got recursive call */
    {
      if (s->mf == A_INVITED ||		/* invite should raise every host */
	  match (s->banmask, c) > 0)	/* push host as it is in listfile */
	_push_listfile_mode (s->net, s->chan->nicks, s->mbuf, s->mf, 1, c);
    }
    else if ((s->id = FindLID (c)) != ID_REM)	/* it's Lname */
    {
      if (iface->qsize == 0)		/* check if we can do recursion */
      {
	Get_Hostlist (iface, s->id);	/* get hosts (to queue tail) */
	while (Get_Request());		/* recursion! */
      }
      else				/* or else just ignore... */
	Add_Request (I_LOG, "*", F_WARN,
		     "irc-channel management: cannot raise %s for %s.",
		     s->type, c);
      s->id = ID_REM;
    }
    else					/* it's nonamed exempt/invite */
      _push_listfile_mode (s->net, s->chan->nicks, s->mbuf, s->mf, 1, c);
  } while (*(c = next));
  return REQ_OK;
}

static void _ircch_raise_exempts (IRC *net, CHANNEL *chan, char *banmask,
				  modebuf *mbuf)
{
  INTERFACE *tmp;
  _ircch_list_raise_struct s;

  s.net = net;
  s.chan = chan;
  s.mbuf = mbuf;
  s.type = "exempt";
  s.mf = A_EXEMPT;
  s.banmask = banmask;
  s.id = ID_REM;
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircch_list_raise_receiver, NULL);
  tmp->data = &s;			/* pass parameters to receiver */
  Set_Iface (tmp);			/* for Get_Request() */
  /* get exempts for channel */
  Get_Clientlist (tmp, U_ACCESS, chan->chi->name, banmask);
  while (Get_Request());
  /* get exempts for network too */
  Get_Clientlist (tmp, U_ACCESS, net->name, banmask);
  while (Get_Request());
  Unset_Iface();
  tmp->data = NULL;			/* it's not allocated you know */
  tmp->ift = I_DIED;			/* we done with it */
}

static void _ircch_raise_invites (IRC *net, CHANNEL *chan, modebuf *mbuf)
{
  INTERFACE *tmp;
  _ircch_list_raise_struct s;

  s.net = net;
  s.chan = chan;
  s.mbuf = mbuf;
  s.type = "invite";
  s.mf = A_INVITED;
  /* s.banmask unused */
  s.id = ID_REM;
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircch_list_raise_receiver, NULL);
  tmp->data = &s;			/* pass parameters to receiver */
  Set_Iface (tmp);			/* for Get_Request() */
  /* get invites for channel and globals */
  Get_Clientlist (tmp, U_INVITE, chan->chi->name, "*");
  while (Get_Request());
  Unset_Iface();
  tmp->data = NULL;			/* it's not allocated you know */
  tmp->ift = I_DIED;			/* we done with it */
}

static void _kickban_user (IRC *net, LINK *target, modebuf *mbuf,
			   char *reason)
{
  if (target->nick->id != ID_REM)
  {
    INTERFACE *tmp;
    _ircch_list_raise_struct s;

    s.net = net;
    s.chan = target->chan;
    s.mbuf = mbuf;
    /* s.type unused */
    s.mf = A_DENIED;
    s.banmask = target->nick->host;
    s.id = target->nick->id;
    tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircch_list_raise_receiver, NULL);
    tmp->data = &s;			/* pass parameters to receiver */
    Set_Iface (tmp);			/* for Get_Request() */
    Get_Hostlist (tmp, s.id);		/* get hosts */
    while (Get_Request());		/* raise ban for it */
    Unset_Iface();
    tmp->data = NULL;			/* it's not allocated you know */
    tmp->ift = I_DIED;			/* we done with it */
  }
  else
  {
    char mask[HOSTMASKLEN+1];

    _make_literal_mask (mask, target->nick->host, sizeof(mask));
    _push_mode (net, target, mbuf, A_DENIED, 1, mask);
    _push_kick (net, target, mbuf, reason ? reason : "you are banned");
  }
}

static void _recheck_modes (IRC *net, LINK *target, userflag rf,
			    userflag cf, modebuf *mbuf, int firstjoined)
{
  clrec_t *cl;
  char *greeting, *c;

  /* check server/channel user's op/voice status to take */
  if ((target->mode & A_ADMIN) &&			/* is an admin */
      ((rf & U_DEOP) ||					/* must be deopped */
       (!(rf & U_MASTER) && (cf & U_DEOP))))		/* +bitch */
    _push_mode (net, target, mbuf, A_ADMIN, 0, NULL);
  else if ((target->mode & A_OP) &&			/* is an op */
	   ((rf & U_DEOP) ||				/* must be deopped */
	    (!(rf & U_OP) && (cf & U_DEOP))))		/* +bitch */
    _push_mode (net, target, mbuf, A_OP, 0, NULL);
  else if ((target->mode & A_HALFOP) &&			/* is a halfop */
	   ((rf & U_DEOP) ||				/* must be deopped */
	    (!(rf & U_HALFOP) && (cf & U_DEOP))))	/* +bitch */
    _push_mode (net, target, mbuf, A_HALFOP, 0, NULL);
  else if ((target->mode & A_VOICE) &&			/* is voiced */
	   (rf & U_QUIET))				/* must be quiet */
    _push_mode (net, target, mbuf, A_VOICE, 0, NULL);
  /* check server/channel user's op/voice status to give */
  if (!(target->mode & A_OP) &&				/* isn't op */
      !(rf & U_DEOP) && (rf & U_OP) &&			/* may be opped */
      ((rf & U_AUTO) || (cf & U_OP)))			/* +autoop */
    _push_mode (net, target, mbuf, A_OP, 1, NULL);
  else if (!(target->mode & (A_HALFOP | A_OP)) &&	/* isn't [half]op */
	   !(rf & U_DEOP) && (rf & U_HALFOP) &&		/* may be halfopped */
	   ((rf & U_AUTO) || (cf & U_OP)) &&		/* +autoop */
	   (net->features & L_HASHALFOP))
    _push_mode (net, target, mbuf, A_HALFOP, 1, NULL);
  else if (!(target->mode & (A_VOICE | A_HALFOP | A_OP)) && /* hasn't voice/op */
	   !(rf & U_QUIET) &&				/* may be voiced */
	   ((rf & U_SPEAK) ||				/* autovoice */
	    ((rf & U_VOICE) && (cf & U_VOICE))))	/* +autovoice */
    _push_mode (net, target, mbuf, A_VOICE, 1, NULL);
  /* greeting user if it is first joined after enough absence */
  DBG ("chmanagement:checking for greeting:%d:%c:%s:%c:%s", firstjoined,
	(cf&U_SPEAK) ? '+' : '-', target->nick->lname,
	(target->chan->id==ID_REM) ? '-' : '+', target->chan->chi->name);
  if (firstjoined && (cf & U_SPEAK) && target->nick->lname &&
      target->chan->id != ID_REM)
  {
    if ((cl = Lock_Clientrecord (target->nick->lname)))
    {
      greeting = safe_strdup (Get_Field (cl, target->chan->chi->name, NULL));
      Unlock_Clientrecord (cl);
      if (greeting)
      {
	if ((c = strchr (target->nick->host, '!')))
	  *c = 0;
	Add_Request (I_SERVICE, target->chan->chi->name, F_T_MESSAGE, "%s: %s",
		     target->nick->host, greeting);
	if (c)
	  *c = '!';
	FREE (&greeting);
      }
      else DBG ("chmanagement:no greeting found");
    }
  }
}


void ircch_recheck_modes (IRC *net, LINK *target, userflag sf, userflag cf,
			  char *info, int x)
{
  userflag rf;
  modebuf mbuf;

  if (!target)
    return;		/* I cannot have any permissions to operate */
  if (Time - target->lmct < ircch_mode_timeout)
    return;		/* don't push too fast modechanges, it will abuse */
  _make_modechars (mbuf.modechars, net);
  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  /* make resulting flags */
  rf = _make_rf (net, sf, cf);
  /* first of all check if user has access: channel and U_ACCESS has priority */
  if (!(rf & U_ACCESS) && (rf & U_DENY))
    _kickban_user (net, target, &mbuf, info);
  else
    _recheck_modes (net, target, rf,
		    Get_Clientflags (target->chan->chi->name, ""), &mbuf, x);
  _flush_mode (net, target->chan, &mbuf);
}

static void _ircch_expire_exempts (IRC *net, CHANNEL *ch, modebuf *mbuf)
{
  LIST *list, *list2;
  clrec_t *cl;
  userflag uf, cf;

  /* check exceptions and remove all expired if no matched bans left */
  for (list = ch->exempts; list; list = list->next)
  {
    for (list2 = ch->bans; list2; list2 = list2->next)
      if (match (list2->what, list->what) > 0)	/* there is a ban... */
	break;
    if (list2)
      continue;					/* ...so keep it */
    if ((cl = Find_Clientrecord (list->what, NULL, &uf, &net->name[1])))
    {
      cf = Get_Flags (cl, ch->chi->name);
      Unlock_Clientrecord (cl);
      if ((uf & (U_ACCESS | U_NOAUTH)) == (U_ACCESS | U_NOAUTH) ||
	  (cf & (U_ACCESS | U_NOAUTH)) == (U_ACCESS | U_NOAUTH))
	continue;					/* it's sticky */
    }
    Add_Request (I_LOG, ch->chi->name, F_MODES, "Exception %s on %s expired.",
		 list->what, ch->chi->name);
    _push_mode (net, ch->nicks, mbuf, A_EXEMPT, 0, list->what);
  }
}

static void _ircch_expire_invites (IRC *net, CHANNEL *ch, modebuf *mbuf)
{
  /* TODO: check invites and remove all not-matched to Listfile? */
}

/* do channel mode change parsing, origin may be NULL if it came from server */
int ircch_parse_modeline (IRC *net, CHANNEL *chan, LINK *origin, char *prefix,
			  userflag uf, bindtable_t *mbt, bindtable_t *kbt,
			  int parc, char **parv)
{
  LINK *me, *target;
  char *pstr, *schr;
  LIST **list;
  binding_t *bind;
  char mf, mc;
  userflag ocf, orf, trf, gcf;
  modeflag mch;
  int nextpar, nignpar;
  clrec_t *cr;
  char buf[STRING];
  modebuf mbuf;

  nextpar = nignpar = 0;
  me = _find_me_op (net, chan);
  _make_modechars (mbuf.modechars, net);
  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  if (origin && origin->nick->lname)
    orf = _make_rf (net, uf,
		    (ocf = Get_Clientflags (origin->nick->lname, chan->chi->name)));
  else
    ocf = orf = 0;					/* server nethack? */
  gcf = Get_Clientflags (chan->chi->name, NULL);
  /* parse parameters */
  while (nextpar < parc)
  {
    pstr = parv[nextpar++];
    mf = 0;
    DBG ("ircch_parse_modeline: parameter %s #%d/%d", pstr, nextpar, parc);
    while (*pstr)
    {
      mc = *pstr++;
      list = NULL;
      mch = 0;
      target = origin;
      schr = NULL;
      switch (mc)
      {
	case '-':
	case '+':
	  mf = mc;
	  break;
	case 'b':
	  if (nextpar == parc)			/* oops, no parameter */
	    break;
	  schr = parv[nextpar++];
	  mch = A_DENIED;
	  list = &chan->bans;
	  break;
	case 'e':
	  if (nextpar == parc)			/* oops, no parameter */
	    break;
	  schr = parv[nextpar++];
	  mch = A_EXEMPT;
	  list = &chan->exempts;
	  break;
	case 'I':
	  if (nextpar == parc)			/* oops, no parameter */
	    break;
	  schr = parv[nextpar++];
	  mch = A_INVITED;
	  list = &chan->invites;
	  break;
	case 'k':
	  if (nextpar == parc)			/* oops, no parameter */
	    break;
	  schr = parv[nextpar++];
	  mch = A_KEYSET;
	  break;
	case 'l':
	  if (mf == '+')
	  {
	    if (nextpar == parc)		/* oops, no parameter */
	      break;
	    schr = parv[nextpar++];
	  }
	  mch = A_LIMIT;
	  break;
	default:
	  schr = memchr (mbuf.modechars, mc, sizeof(mbuf.modechars));
	  if (schr)
	    mch = 1 << (schr - mbuf.modechars);
	  else
	    mch = 0;
	  if (mch & (A_ADMIN | A_OP | A_HALFOP | A_VOICE))
	  {
	    if (nextpar == parc)		/* oops, no parameter */
	      mch = 0;
	    else
	      schr = parv[nextpar++];
	  }
	  else
	    schr = NULL;
	  if (mch && schr)
	  {
	    if (net->lc)
	    {
	      net->lc (buf, schr, sizeof(buf));
	      target = ircch_find_link (net, buf, chan);
	    }
	    else
	      target = ircch_find_link (net, schr, chan);
	  }
      }
      if (mc == mf)
	continue;
      nignpar++;			/* modechanges counter */
      if (!mf || !mch)
      {
	/* bad modechange! */
	WARNING ("ircch_parse_modeline: invalid char '%c' ignored", mc);
	continue;
      }
      snprintf (buf, sizeof(buf), "%s %c%c%s%s", chan->chi->name, mf, mc,
		schr ? " " : "", NONULL(schr));
      for (bind = NULL; (bind = Check_Bindtable (mbt, buf, uf, ocf, bind)); )
      {
	if (bind->name)		/* note for eggdrop's users: prefix handled */
	  RunBinding (bind, prefix,	/* a bit different for server mode */
		      (origin && origin->nick->lname) ? origin->nick->lname : "*",
		      chan->chi->name, NULL, -1, NextWord (buf));
	else
	  bind->func (prefix, origin ? origin->nick->lname : NULL, chan->chi,
		      NextWord (buf));
      }
      if (list)				/* add/remove mask [schr] in [list] */
      {
	if (!(orf & U_OWNER) && mf == '+' && (gcf & U_DENY))
	  _push_mode (net, target, &mbuf, mch, 0, schr);
	if (mf == '-')
	{
	  LIST *item;

	  if ((item = ircch_find_mask (*list, schr)))
	    ircch_remove_mask (list, item);
	  /* if ban was removed then remove all matched dynamic exceptions */
	  if (mc == 'b' && !(net->features & L_NOEXEMPTS) &&
	      !(Get_Clientflags (chan->chi->name, "") & U_NOAUTH))
	    _ircch_expire_exempts (net, chan, &mbuf);
	  continue;
	}
	else if (origin)
	  ircch_add_mask (list, origin->nick->host,
			  safe_strlen (origin->nick->name), schr);
	else
	  ircch_add_mask (list, "", 0, schr);
	/* start enforcer if enforcing is on and ban is raised */
	if ((gcf & U_AUTO) && chan->tid == -1 && mc == 'b' && mf == '+')
	  chan->tid = NewTimer (chan->chi->ift, chan->chi->name, S_LOCAL,
				ircch_enforcer_time, 0, 0, 0);
	/* set matched exceptions while ban is set */
	if (mc == 'b' &&		/* ignore +e and +I */
	    !(net->features & L_NOEXEMPTS) &&
	    !(Get_Clientflags (chan->chi->name, "") & U_NOAUTH))
	  _ircch_raise_exempts (net, chan, schr, &mbuf);
      }
      else if (mch)
      {
	/* check for modelocks and reverse modechange */
	if (!(orf & U_OWNER))		/* owner may change any modes */
	{
	  if (mf == '-' && (mch & chan->mlock))
	  {
	    if (mch & A_LIMIT)
	    {
	      snprintf (buf, sizeof(buf), "%d", chan->limit);
	      _push_mode (net, target, &mbuf, mch, 1, buf);
	    }
	    else if (mch & A_KEYSET)
	      _push_mode (net, target, &mbuf, mch, 1, chan->key);
	    else
	      _push_mode (net, target, &mbuf, mch, 1, NULL);
	  }
	  else if (mf == '+' && (mch & chan->munlock))
	    _push_mode (net, target, &mbuf, mch, 0, NULL);
	}
	/* apply changes */
	if (mch & A_KEYSET)
	{
	  if (mf == '-')
	    schr = NULL;
	  for (bind = NULL; (bind = Check_Bindtable (mbt, chan->chi->name, uf,
						     ocf, bind)); )
	    if (!bind->name)
	      bind->func (chan->chi->name, prefix,
			  (origin && origin->nick->lname) ? origin->nick->lname : NULL,
			  orf, schr);
	  FREE (&chan->key);
	  chan->key = safe_strdup (schr);
	  cr = Lock_Clientrecord (chan->chi->name);
	  if (cr)			/* oops, key changed! memorize it! */
	  {
	    Add_Request (I_LOG, "*", F_WARN, "Key for channel %s was changed!",
			 chan->chi->name);
	    if (!Set_Field (cr, "passwd", chan->key, 0))
	      Add_Request (I_LOG, "*", F_WARN, "Could not save key for %s!",
			   chan->chi->name);
	    Unlock_Clientrecord (cr);
	  }
	}
	else if (mch & A_LIMIT)
	{
	  if (mf == '-')
	    chan->limit = 0;
	  else
	    chan->limit = atoi (schr);
	}
	else if (schr)			/* modechange for [schr] on channel */
	{
	  if (!target)
	  {
	    ERROR ("ircch_parse_modeline: not found target %s for %c%c in %s!",
		   schr, mf, mc, chan->chi->name);
	    continue;
	  }
	  if (mf == '-')
	    target->mode &= ~mch;
	  else
	    target->mode |= mch;
	  if (target->nick->split)
	  {
	    dprint (4, "ircch_parse_modeline: possible netjoined %s(%s)",
		    prefix, target->nick->split->servers);
	    if (!strcmp (NextWord(target->nick->split->servers), prefix))
	      nignpar--;		/* target is returning from netsplit */
	  }
	  if (!(orf & U_MASTER))	/* masters may change modes */
	  {
	    if (target->nick->lname)
	      trf = _make_rf (net,	/* mix global and channel ones */
			Get_Clientflags (target->nick->lname, NULL) |
			Get_Clientflags (target->nick->lname, &net->name[1]),
			Get_Clientflags (target->nick->lname, chan->chi->name));
	    else
	      trf = 0;
	    if (mf == '-' && (mch & (A_OP | A_HALFOP)) && (gcf & U_MASTER) &&
		!(gcf & U_DEOP) && !(trf & U_DEOP) &&
		(trf & (U_OP | U_HALFOP | U_FRIEND))) /* protect ops/friends */
	      _push_mode (net, target, &mbuf, mch, 1, NULL);
	    else
	      _recheck_modes (net, target, trf, gcf, &mbuf, 0);
	  }
	}
	else if (mf == '-')		/* modechange for whole channel */
	{
	  chan->mode &= ~mch;
	  /* if '-i' then clear invites list because server do that too */
	  if (mc == 'i') while (chan->invites)
	    ircch_remove_mask (&chan->invites, chan->invites);
	}
	else
	{
	  chan->mode |= mch;
	  /* if '+i' then raise every +I we have in Listfile for the channel */
	  if (mc == 'i')
	    _ircch_raise_invites (net, chan, &mbuf);
	}
      }
    }
  }
  _flush_mode (net, chan, &mbuf);
  return nignpar;
}

void ircch_parse_configmodeline (IRC *net, CHANNEL *chan, char *mode)
{
  char mf, mc;
  modeflag mch;
  char *c;
  modebuf mbuf;

  chan->mlock = chan->munlock = 0;		/* reset it at first */
  _make_modechars (mbuf.modechars, net);
  mf = 0;
  while (*mode && *mode != ' ')	/* it may have second parameter - limit */
  {
    mc = *mode++;
    switch (mc)
    {
      case '-':
      case '+':
	mf = mc;
	mch = 0;
	break;
      case 'k':
	mch = A_KEYSET;
	break;
      case 'l':
	mch = A_LIMIT;
	break;
      default:
	c = memchr (mbuf.modechars, mc, sizeof(mbuf.modechars));
	if (c)
	  mch = 1 << (c - mbuf.modechars);
	else
	  mch = 0;
    }
    if (!mch || !mf)
      continue;
    if (mf == '-')		/* modechange for whole channel */
    {
      chan->munlock |= mch;
      chan->mlock &= ~mch;
    }
    else
    {
      chan->mlock |= mch;
      chan->munlock &= ~mch;
    }
  }
  if (chan->mlock & A_KEYSET)
    chan->limit = atoi (NextWord (mode));
  else
    chan->limit = 0;
}

void ircch_enforcer (IRC *net, CHANNEL *chan)
{
  LINK *link;
  clrec_t *clr;
  userflag rf, cf;
  LIST *ban, *ex;
  modebuf mbuf;

  _make_modechars (mbuf.modechars, net);
  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  cf = Get_Clientflags (chan->chi->name, "");	/* get all flags */
  for (link = chan->nicks; link; link = link->prevnick)
    if (!(link->mode & (A_ADMIN | A_OP | A_HALFOP)) || !(cf & U_FRIEND))
    {
      if ((clr = Lock_byLID (link->nick->id)))	/* we need to check excempts */
      {
	rf = _make_rf (net,
		       Get_Flags (clr, NULL) | Get_Flags (clr, &net->name[1]),
		       Get_Flags (clr, chan->chi->name));
	Unlock_Clientrecord (clr);
      }
      else
	rf = 0;
      if (rf & (U_FRIEND | U_MASTER | U_OP | U_HALFOP | U_ACCESS))
	continue;
      for (ban = chan->bans, ex = NULL; ban; ban = ban->next)
	if (match (ban->what, link->nick->host) > 0)
	{
	  for (ex = chan->exempts; ex; ex = ex->next)
	    if (match (ban->what, ex->what) > 0 &&
		match (ex->what, link->nick->host) > 0)
	      break;
	  if (!ex)
	    break;
	}
      if (ban && !ex)
	_push_kick (net, link, &mbuf, "you are banned");
    }
  _flush_mode (net, chan, &mbuf);
}

static void _ircch_expire_bans (IRC *net, CHANNEL *ch, modebuf *mbuf)
{
  time_t t;
  LIST *list;
  clrec_t *cl;
  userflag uf, cf;

  /* check bans and remove all expired (unsticky) */
  if (ircch_ban_keep > 0)
  {
    t = Time - ircch_ban_keep * 60;
    for (list = ch->bans; list; list = list->next)
    {
      if (list->since > t)
	continue;
      if ((cl = Find_Clientrecord (list->what, NULL, &uf, &net->name[1])))
      {
	cf = Get_Flags (cl, ch->chi->name);
	Unlock_Clientrecord (cl);
	if ((uf & (U_DENY | U_NOAUTH)) == (U_DENY | U_NOAUTH) ||
	    (cf & (U_DENY | U_NOAUTH)) == (U_DENY | U_NOAUTH))
	  continue;					/* it's sticky */
      }
      Add_Request (I_LOG, ch->chi->name, F_MODES, "Ban %s on %s expired.",
		   list->what, ch->chi->name);
      _push_mode (net, ch->nicks, mbuf, A_DENIED, 0, list->what);
    }
  }
}

void ircch_expire (IRC *net, CHANNEL *ch)
{
  modebuf mbuf;

  if ((Get_Clientflags (ch->chi->name, "") & U_NOAUTH))	/* -dynamic */
    return;
  _make_modechars (mbuf.modechars, net);
  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  _ircch_expire_bans (net, ch, &mbuf);
  if (!(net->features & L_NOEXEMPTS))
    _ircch_expire_exempts (net, ch, &mbuf);
  if (!(ch->mode & A_INVITEONLY))
    _ircch_expire_invites (net, ch, &mbuf);
  _flush_mode (net, ch, &mbuf);
}


/* --- "ss-irc" bindings ------------------------------------------------------
 *   int func(peer_t *who, INTERFACE *where, char *args);
 */

		/* .adduser [!]nick [lname] */
BINDING_TYPE_ss_ (ssirc_adduser);
static int ssirc_adduser (peer_t *who, INTERFACE *where, char *args)
{
  IRC *net;
  char *c, *as;
  NICK *nick;
  clrec_t *u;
  int i;
  userflag tf;
  char name[LNAMELEN+1];
  char mask[HOSTMASKLEN+1];

  /* find and check target */
  if (!where)
    return 0;
  ircch_find_service (where->name, &net);
  if (!net || !args)
    return 0;
  if (args[0] == '!')
    i = 1;
  else
    i = 0;
  c = strchr (&args[i], ' ');
  if (c)
  {
    as = NextWord (c);
    *c = 0;
  }
  else
    as = &args[i];
  if (net->lc)
  {
    net->lc (name, as, sizeof(name));
    as = name;
    net->lc (mask, &args[i], sizeof(mask));
    nick = ircch_retry_nick (net, mask);
  }
  else
    nick = ircch_retry_nick (net, &args[i]);
  if (nick && nick->lname)
  {
    New_Request (who->iface, 0, _("adduser: %s is already known as %s."),
		 &args[i], nick->lname);
    if (c)
      *c = ' ';
    return 0;
  }
  if (nick && !nick->host)
  {
    New_Request (who->iface, 0, _("Could not find host of %s."), &args[i]);
    if (c)
      *c = ' ';
    return 0;
  }
  if (c)
    *c = ' ';
  if (!nick)
    return 0;
  if (i == 1)
    _make_literal_mask (mask, nick->host, sizeof(mask));
  else
    _make_mask (mask, nick->host, sizeof(mask));
  /* add mask (mask) to target (as) */
  u = Lock_Clientrecord (as);
  if (u)	/* existing client */
  {
    tf = Get_Flags (u, NULL);
    /* master may change only own or not-masters masks */
    if (!(tf & (U_MASTER | U_OWNER)) || (who->uf & U_OWNER) ||
	!safe_strcmp (as, who->iface->name))
      i = Add_Mask (u, mask);
    else
    {
      New_Request (who->iface, 0, _("Permission denied."));
      i = 1;	/* report it to log anyway */
    }
    Unlock_Clientrecord (u);
  }
  else		/* new clientrecord with no flags and no password */
  {
    i = Add_Clientrecord (as, mask, U_ANY);
  }
  return i;	/* nothing more, all rest will be done on next users's event */
}

		/* .deluser [!]nick */
BINDING_TYPE_ss_ (ssirc_deluser);
static int ssirc_deluser (peer_t *who, INTERFACE *where, char *args)
{
  IRC *net;
  NICK *nick;
  CHANNEL *ch;
  clrec_t *u;
  int i;
  userflag tf;
  char mask[HOSTMASKLEN+1];

  /* find and check target */
  if (!where)
    return 0;
  ch = ircch_find_service (where->name, &net);
  if (!net || !args)
    return 0;
  if (args[0] == '!')
    i = 1;
  else
    i = 0;
  if (net->lc)
  {
    net->lc (mask, &args[i], sizeof(mask));
    nick = ircch_retry_nick (net, mask);
  }
  else
    nick = ircch_retry_nick (net, &args[i]);
  if (!nick)
  {
    New_Request (who->iface, 0, _("Could not find nick %s."), &args[i]);
    return 0;
  }
  if (!nick->lname)
  {
    New_Request (who->iface, 0, _("deluser: %s isn't registered."), &args[i]);
    return 0;
  }
  if (!nick->host)
  {
    New_Request (who->iface, 0, _("Could not find host of %s."), &args[i]);
    return 0;
  }
  if (i == 1)
    _make_literal_mask (mask, nick->host, sizeof(mask));
  else
    _make_mask (mask, nick->host, sizeof(mask));
  /* delete mask (mask) from target (as) */
  u = Lock_Clientrecord (nick->lname);
  if (u)	/* existing client */
  {
    tf = Get_Flags (u, NULL) | Get_Flags (u, ch->chi->name);
    /* master may change only own or not-masters masks */
    if (!(tf & (U_MASTER | U_OWNER)) || (who->uf & U_OWNER) ||
	!safe_strcmp (nick->lname, who->iface->name))
      i = Delete_Mask (u, mask);
    else
      New_Request (who->iface, 0, _("Permission denied."));
    Unlock_Clientrecord (u);
    if (i == -1) /* it was last host */
      Delete_Clientrecord (nick->lname);
  }
  else		/* oops! */
  {
    WARNING ("irc:deluser: Lname %s is lost", nick->lname);
  }
  return 1;	/* nothing more, all rest will be done on next users's event */
}

#define ischannelname(a) strchr (CHANNFIRSTCHAR, a[0])

static int _ssirc_say (peer_t *who, INTERFACE *where, char *args, flag_t type)
{
  char target[IFNAMEMAX+1];
  char *c = NULL;

  if (!args)
    return 0;
  if (ischannelname (args))
  {
    args = NextWord_Unquoted (target, args, sizeof(target));
    if (!strchr (target, '@') && !(c = strrchr (where->name, '@')))
    {
      strfcat (target, "@", sizeof(target));
      c = where->name;
    }
    if (c)
      strfcat (target, c, sizeof(target));
    Add_Request (I_SERVICE, target, type, "%s", args);
  }
  else if (!strchr (where->name, '@'))
    return 0;
  else
    New_Request (where, type, "%s", args);
  return 1;
}

		/* .say [channel[@net]] text... */
BINDING_TYPE_ss_ (ssirc_say);
static int ssirc_say (peer_t *who, INTERFACE *where, char *args)
{
  return _ssirc_say (who, where, args, F_T_MESSAGE);
}

		/* .act [channel[@net]] text... */
BINDING_TYPE_ss_ (ssirc_act);
static int ssirc_act (peer_t *who, INTERFACE *where, char *args)
{
  return _ssirc_say (who, where, args, F_T_ACTION);
}

		/* .notice target[@net] text... */
BINDING_TYPE_ss_ (ssirc_notice);
static int ssirc_notice (peer_t *who, INTERFACE *where, char *args)
{
  char target[IFNAMEMAX+1];
  char *c = NULL;

  if (!args)
    return 0;
  args = NextWord_Unquoted (target, args, sizeof(target));
  if (!strchr (target, '@') && !(c = strrchr (where->name, '@')))
  {
    strfcat (target, "@", sizeof(target));
    c = where->name;
  }
  if (c)
    strfcat (target, c, sizeof(target));
  Add_Request (I_CLIENT, target, F_T_NOTICE, "%s", args);
  return 1;
}

		/* .ctcp target[@net] text... */
BINDING_TYPE_ss_ (ssirc_ctcp);
static int ssirc_ctcp (peer_t *who, INTERFACE *where, char *args)
{
  char target[IFNAMEMAX+1];
  char cmd[CTCPCMDMAX+1];
  char *c = NULL;

  if (!args)
    return 0;
  args = NextWord_Unquoted (target, args, sizeof(target));
  if (!strchr (target, '@') && !(c = strrchr (where->name, '@')))
  {
    strfcat (target, "@", sizeof(target));
    c = where->name;
  }
  if (c)
    strfcat (target, c, sizeof(target));
  for (c = cmd; c < &cmd[sizeof(cmd)-1] && *args && *args != ' '; args++)
    *c++ = toupper (((uchar *)args)[0]);
  *c = 0;
  Add_Request (I_CLIENT, target, F_T_CTCP, "%s%s", cmd, args);
  return 1;
}

		/* .topic [channel[@net]] text... */
BINDING_TYPE_ss_ (ssirc_topic);
static int ssirc_topic (peer_t *who, INTERFACE *where, char *args)
{
  char target[IFNAMEMAX+1];
  char *c = NULL; /* "@net" */

  if (!args)
    args = "";
  if (ischannelname (args))
  {
    args = NextWord_Unquoted (target, args, sizeof(target));
    if ((c = strrchr (target, '@')))		/* check for chan@net first */
      *c = 0;
    else if (!(c = strrchr (where->name, '@')))	/* else check for chan */
      return 0;					/* cannot determine network */
  }
  else if (!(c = strrchr (where->name, '@')))	/* check for current network */
    return 0;					/* cannot determine network */
  else if ((size_t)(c - (char *)where->name) >= sizeof(target))
    strfcpy (target, where->name, sizeof(target)); /* it's impossible! */
  else						/* get chan name from where */
    strfcpy (target, where->name, (c - (char *)where->name) + 1);
  Add_Request (I_SERVICE, &c[1], 0, "TOPIC %s :%s", target, args);
  return 1;
}

static CHANNEL *_ssirc_find_target (peer_t *who, INTERFACE *where, char **args,
				    IRC **net, char *b, size_t s, LINK **me)
{
  register char *tgt = *args;
  CHANNEL *ch;

  DBG ("_ssirc_find_target:%s:%s:%s", who->iface->name, where->name, tgt);
  if (tgt == NULL)
    return NULL;
  if (tgt[0] && ischannelname (tgt))
  {
    *args = NextWord_Unquoted (b, tgt, s);
    if (strchr (b, '@'));			/* check for chan@net first */
    else if (where && (tgt = strrchr (where->name, '@'))) /* check for chan */
      strfcat (b, tgt, s);
    else
      return NULL;				/* cannot determine network */
    tgt = b;
  }
  else if (!where)
    return NULL;
  else
    tgt = where->name;
  if (!(ch = ircch_find_service (tgt, net)) || !*net)
  {
    New_Request (who->iface, 0, _("%s isn't IRC channel!"), tgt);
    return NULL;
  }
  if (me)
    *me = _find_me_op (*net, ch);
  return ch;
}

		/* .kick [channel[@net]] nick [reason...] */
BINDING_TYPE_ss_ (ssirc_kick);
static int ssirc_kick (peer_t *who, INTERFACE *where, char *args)
{
  IRC *net;
  CHANNEL *ch;
  LINK *me, *tlink;
  char target[IFNAMEMAX+1];
  char lct[IFNAMEMAX+1];
  char *reason, *tgt;
  userflag uf, tf;
  modebuf mbuf;

  ch = _ssirc_find_target (who, where, &args, &net, target, sizeof(target), &me);
  if (!ch)
    return 0;
  else if (!me)
  {
    New_Request (who->iface, 0, _("No operator priveleges on %s."),
		 where->name);
    return -1;
  }
  _make_modechars (mbuf.modechars, net);
  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  /* TODO: work with nicks list too? */
  reason = NextWord_Unquoted (target, args, sizeof(target));
  if (net->lc)				/* determine and check target */
    net->lc ((tgt = lct), target, sizeof(lct));
  else
    tgt = target;
  if (!(tlink = ircch_find_link (net, tgt, ch)))
  {
    New_Request (who->iface, 0, _("%s isn't on IRC channel %s for me!"),
		 args, where->name);
    return 0;
  }
  /* it does not recheck nick's lname but uses one from last nick's event */
  if (tlink->nick->lname)		/* check seniority */
  {
    uf = _make_rf (net, Get_Clientflags (who->iface->name, NULL) |
		   Get_Clientflags (who->iface->name, &net->name[1]),
		   Get_Clientflags (who->iface->name, ch->chi->name));
    tf = _make_rf (net, Get_Clientflags (tlink->nick->lname, NULL) |
		   Get_Clientflags (tlink->nick->lname, &net->name[1]),
		   Get_Clientflags (tlink->nick->lname, ch->chi->name));
    if ((!(uf & U_MASTER) && (tf & U_MASTER)) ||
	(!(uf & U_OP) && (tf & U_OP)) ||
	(!(uf & U_HALFOP) && (tf & U_HALFOP)))
    {
      New_Request (who->iface, 0, _("Permission denied."));
      return -1;
    }
  }
  _push_kick (net, tlink, &mbuf, *reason ? reason : ircch_default_kick_reason);
  _flush_mode (net, ch, &mbuf);
  return 1;
}

		/* .kickban [channel[@net]] [-|@]nick [reason...] */
BINDING_TYPE_ss_ (ssirc_kickban);
static int ssirc_kickban (peer_t *who, INTERFACE *where, char *args)
{
  IRC *net;
  CHANNEL *ch;
  LINK *me, *tlink;
  char target[IFNAMEMAX+1];
#if IFNAMEMAX > HOSTMASKLEN
  char lct[IFNAMEMAX+1];
#else
  char lct[HOSTMASKLEN+1];
#endif
  char *reason, *tgt;
  char flag;
  userflag uf, tf;
  modebuf mbuf;

  ch = _ssirc_find_target (who, where, &args, &net, target, sizeof(target), &me);
  if (!ch)
    return 0;
  else if (!me)
  {
    New_Request (who->iface, 0, _("No operator priveleges on %s."),
		 where->name);
    return -1;
  }
  if (*args == '-' || *args == '@')	/* eggdrop-style masking */
    flag = *args++;
  else
    flag = 0;
  _make_modechars (mbuf.modechars, net);
  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  reason = NextWord_Unquoted (target, args, sizeof(target));
  if (net->lc)				/* determine and check target */
    net->lc ((tgt = lct), target, sizeof(lct));
  else
    tgt = target;
  if (!(tlink = ircch_find_link (net, tgt, ch)))
  {
    New_Request (who->iface, 0, _("%s isn't on IRC channel %s for me!"),
		 args, where->name);
    return 0;
  }
  /* it does not recheck nick's lname but uses one from last nick's event */
  if (tlink->nick->lname)		/* check seniority */
  {
    uf = _make_rf (net, Get_Clientflags (who->iface->name, NULL) |
		   Get_Clientflags (who->iface->name, &net->name[1]),
		   Get_Clientflags (who->iface->name, ch->chi->name));
    tf = _make_rf (net, Get_Clientflags (tlink->nick->lname, NULL) |
		   Get_Clientflags (tlink->nick->lname, &net->name[1]),
		   Get_Clientflags (tlink->nick->lname, ch->chi->name));
    if ((!(uf & U_MASTER) && (tf & U_MASTER)) ||
	(!(uf & U_OP) && (tf & U_OP)) ||
	(!(uf & U_HALFOP) && (tf & U_HALFOP)))
    {
      New_Request (who->iface, 0, _("Permission denied."));
      return -1;
    }
  }
  if (flag == 0)
    _make_mask (lct, tlink->nick->host, sizeof(lct));
  else if (flag == '-')
    _make_literal_mask (lct, tlink->nick->host, sizeof(lct));
  else /* '@' */
    snprintf (lct, sizeof(lct), "*!*%s", strchr (tlink->nick->host, '@'));
  _push_mode (net, tlink, &mbuf, A_DENIED, 1, lct);
  _push_kick (net, tlink, &mbuf, *reason ? reason : ircch_default_kick_reason);
  _flush_mode (net, ch, &mbuf);
  return 1;
}

static int _ssirc_setmode (peer_t *who, INTERFACE *where, char *args,
			    modeflag mf, int set)
{
  IRC *net;
  CHANNEL *ch;
  LINK *me, *tlink;
  char target[IFNAMEMAX+1];
#if IFNAMEMAX > HOSTMASKLEN
  char lct[IFNAMEMAX+1];
#else
  char lct[HOSTMASKLEN+1];
#endif
  char *tgt;
  modebuf mbuf;

  args = NextWord_Unquoted (target, args, sizeof(target));
  ch = _ssirc_find_target (who, where, &args, &net, lct, sizeof(lct), &me);
  if (!ch)
    return 0;
  else if (!me)
  {
    New_Request (who->iface, 0, _("No operator priveleges on %s."),
		 where->name);
    return -1;
  }
  _make_modechars (mbuf.modechars, net);
  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  /* TODO: work with nicks list too! */
  if (net->lc)				/* determine and check target */
    net->lc ((tgt = lct), target, sizeof(lct));
  else
    tgt = target;
  if (!(tlink = ircch_find_link (net, tgt, ch)))
  {
    New_Request (who->iface, 0, _("%s isn't on IRC channel %s for me!"),
		 args, where->name);
    return 0;
  }
  /* TODO: make some eggdrop-style assumptions for giving flags? */
  _push_mode (net, tlink, &mbuf, mf, set, NULL);
  _flush_mode (net, ch, &mbuf);
  return 1;
}

		/* .voice nick [channel[@net]] */
BINDING_TYPE_ss_ (ssirc_voice);
static int ssirc_voice (peer_t *who, INTERFACE *where, char *args)
{
  return _ssirc_setmode (who, where, args, A_VOICE, 1);
}

		/* .devoice nick [channel[@net]] */
BINDING_TYPE_ss_ (ssirc_devoice);
static int ssirc_devoice (peer_t *who, INTERFACE *where, char *args)
{
  return _ssirc_setmode (who, where, args, A_VOICE, 0);
}

		/* .op nick [channel[@net]] */
BINDING_TYPE_ss_ (ssirc_op);
static int ssirc_op (peer_t *who, INTERFACE *where, char *args)
{
  return _ssirc_setmode (who, where, args, A_OP, 1);
}

		/* .deop nick [channel[@net]] */
BINDING_TYPE_ss_ (ssirc_deop);
static int ssirc_deop (peer_t *who, INTERFACE *where, char *args)
{
  return _ssirc_setmode (who, where, args, A_OP, 0);
}

		/* .hop nick [channel[@net]] */
BINDING_TYPE_ss_ (ssirc_hop);
static int ssirc_hop (peer_t *who, INTERFACE *where, char *args)
{
  return _ssirc_setmode (who, where, args, A_HALFOP, 1);
}

		/* .dehop nick [channel[@net]] */
BINDING_TYPE_ss_ (ssirc_dehop);
static int ssirc_dehop (peer_t *who, INTERFACE *where, char *args)
{
  return _ssirc_setmode (who, where, args, A_HALFOP, 0);
}

		/* .reset [+b|+e|+I] [channel[@net]] */
BINDING_TYPE_ss_ (ssirc_reset);
static int ssirc_reset (peer_t *who, INTERFACE *where, char *args)
{
  modeflag mf = 0;
  IRC *net;
  CHANNEL *ch;
  LINK *me;
  char chn[IFNAMEMAX+1];
  modebuf mbuf;

  if (*args == '+')
  {
    do
    {
      if (*++args == 'b')
	mf |= A_DENIED;
      else if (*args == 'e')
	mf |= A_EXEMPT;
      else if (*args == 'I')
	mf |= A_INVITED;
    } while (*args && *args != ' ');
  }
  else
    mf = A_DENIED | A_EXEMPT | A_INVITED;
  ch = _ssirc_find_target (who, where, &args, &net, chn, sizeof(chn), &me);
  if (!ch)
    return 0;
  else if (!me)
  {
    New_Request (who->iface, 0, _("No operator priveleges on %s."),
		 where->name);
    return -1;
  }
  _make_modechars (mbuf.modechars, net);
  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  if (mf & A_DENIED)
  {
    _ircch_expire_bans (net, ch, &mbuf);
    ircch_enforcer (net, ch);
  }
  if (mf & A_EXEMPT && !(net->features & L_NOEXEMPTS))
    _ircch_expire_exempts (net, ch, &mbuf);
  if (mf & A_INVITED && ch->mode & A_INVITEONLY)
  {
    _ircch_expire_invites (net, ch, &mbuf);
    _ircch_raise_invites (net, ch, &mbuf);
  }
  return 1;
}

		/* .invite nick [channel[@net]] */
BINDING_TYPE_ss_ (ssirc_invite);
static int ssirc_invite (peer_t *who, INTERFACE *where, char *args)
{
  IRC *net;
  CHANNEL *ch;
  LINK *me;
  char *c;
  char chn[IFNAMEMAX+1];
  char target[IFNAMEMAX+1];

  args = NextWord_Unquoted (target, args, sizeof(target));
  ch = _ssirc_find_target (who, where, &args, &net, chn, sizeof(chn), &me);
  if (!ch)
    return 0;
  else if ((ch->mode & A_INVITEONLY) && !me)
  {
    New_Request (who->iface, 0, _("No operator priveleges on %s."),
		 where->name);
    return -1;
  }
  c = strrchr (chn, '@');
  *c = 0;
  New_Request (net->neti, 0, "INVITE %s %s", target, chn);
  return 1;
}

void ircch_set_ss (void)
{
#define NB(a,b,c) Add_Binding ("ss-irc", #a, b, c, &ssirc_##a, NULL)
  NB (adduser,	U_MASTER, U_MASTER);
  NB (deluser,	U_MASTER, U_MASTER);
  NB (say,	U_SPEAK, U_SPEAK);
  NB (act,	U_SPEAK, U_SPEAK);
  NB (ctcp,	U_SPEAK, U_SPEAK);
  NB (notice,	U_SPEAK, U_SPEAK);
  NB (topic,	U_SPEAK, U_SPEAK);
  NB (kick,	U_OP, U_OP);
  NB (kickban,	U_OP, U_OP);
  NB (voice,	U_HALFOP, U_HALFOP);
  NB (devoice,	U_HALFOP, U_HALFOP);
  NB (op,	U_OP, U_OP);
  NB (deop,	U_OP, U_OP);
  NB (hop,	U_OP, U_OP);
  NB (dehop,	U_OP, U_OP);
  NB (reset,	U_OP, U_OP);
  NB (invite,	U_HALFOP, U_HALFOP);
#undef NB
}

void ircch_unset_ss (void)
{
#define NB(a) Delete_Binding ("ss-irc", &ssirc_##a, NULL)
  NB (adduser);
  NB (deluser);
  NB (say);
  NB (act);
  NB (ctcp);
  NB (notice);
  NB (topic);
  NB (kick);
  NB (kickban);
  NB (voice);
  NB (devoice);
  NB (op);
  NB (deop);
  NB (hop);
  NB (dehop);
  NB (reset);
  NB (invite);
#undef NB
}
