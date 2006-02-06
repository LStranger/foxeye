/*
 * Copyright (C) 2005-2006  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 */

#include "foxeye.h"

#include <pthread.h>

#include "tree.h"
#include "wtmp.h"
#include "init.h"
#include "sheduler.h"
#include "irc-channel.h"

extern long int ircch_enforcer_time;		/* from irc-channel.c */

#define	MODECHARSMAX	32	/* long int capable */
#define	MODECHARSFIX	3	/* specials, see net_t structure */

typedef struct
{
  uchar mc[MODECHARSMAX];	/* chars of modes */
  uchar mcf[MODECHARSFIX];	/* references to above for specials */
  uchar admin, anonymous, halfop;
} mch_t;

typedef struct
{
  size_t changes, pos, apos;
  char modechars[MODECHARSMAX];
  const char *cmd;
  char mchg[STRING];
  char args[STRING];
} modebuf_t;

static mch_t *ModeChars = NULL;			

/* TODO: extra channel modes:
    Rizon: MNORZ
    irchighway: AKMNORS
    ChatSpike: a,fruzACGKL,MNOQRSTV */

static void _make_modechars (char *modechars, net_t *net)
{
  unsigned long int i, m;

  if (!ModeChars)
  {
    ModeChars = safe_calloc (1, sizeof(mch_t));
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

static link_t *_find_me_op (net_t *net, ch_t *ch)
{
  link_t *me;

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
static userflag _make_rf (net_t *net, userflag sf, userflag cf)
{
  userflag rf, tf;

  rf = cf & (U_DENY | U_ACCESS);
  if (!rf)
    rf = sf & (U_DENY | U_ACCESS);
  rf |= (cf | sf) & (U_FRIEND | U_OWNER | U_BOT);
  if (!(net->features & L_HASADMIN))
  {
    tf = U_HALFOP | U_OP | U_DEOP;
    rf |= (cf | sf) & U_MASTER;
  }
  else
    tf = U_MASTER | U_HALFOP | U_OP | U_DEOP;
  if (cf & (U_QUIET | U_VOICE | U_SPEAK))
    rf |= cf & (U_QUIET | U_VOICE | U_SPEAK);
  else
    rf |= sf & (U_QUIET | U_VOICE | U_SPEAK);
  if (cf & tf)
    rf |= cf & (tf | U_AUTO);
  else
    rf |= sf & (tf | U_AUTO);
  return rf;
}

static char *_make_mask (char *mask, char *uh, size_t s, int igntld)
{
  register char *c, *m;
  int n;

  if (s < 9) return NULL;	/* it cannot be true, at least "*!*@*.xx\0" */
  m = mask;
  n = 0;
  for (c = uh; *c && *c != '!'; c++);
  *m++ = '*';
  if (*c == '!' && igntld && (c[1] == '~' || c[1] == '^'))
  {
    *m++ = '!';
    c += 2;
  }
  while (m < &mask[s-3] && *c)
  {
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

static void _flush_mode (net_t *net, ch_t *chan, modebuf_t *mbuf)
{
  char *c;

  if (mbuf->cmd == NULL || mbuf->changes == 0)
    return;
  c = strrchr (chan->chi->name, '@');
  if (c) *c = 0;
  mbuf->mchg[mbuf->pos] = 0;
  mbuf->args[mbuf->apos] = 0;
  New_Request (net->neti, 0, "%s %s %s %s", mbuf->cmd, chan->chi->name,
	       mbuf->mchg, mbuf->args);
  if (c) *c = '@';
  mbuf->cmd = NULL;
  mbuf->changes = mbuf->pos = mbuf->apos = 0;
}

static void _push_mode (net_t *net, link_t *target, modebuf_t *mbuf,
			modeflag mch, int add, char *mask)
{
  const char CMD_MODE[] = "MODE";
  size_t i, m;

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
  if (!i)
    return;
  if (i >= sizeof(mbuf->args) - mbuf->apos) /* it's impossible but anyway */
    i = sizeof(mbuf->args) - mbuf->apos - 1;
  if (mbuf->apos)
    mbuf->args[mbuf->apos++] = ' ';
  memcpy (&mbuf->args[mbuf->apos], mask, i);
  mbuf->apos += i;
}

static void _push_kick (net_t *net, link_t *target, modebuf_t *mbuf,
		        char *reason)
{
  const char CMD_KICK[] = "KICK";
  char *c;
  size_t i, m;

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
  if (mbuf->mchg)
    mbuf->mchg[mbuf->pos++] = ',';
  memcpy (&mbuf->mchg[mbuf->pos], target->nick->host, m);
  mbuf->pos += m;
  mbuf->changes++;
}

static void _kickban_user (net_t *net, link_t *target, modebuf_t *mbuf,
			   char *reason)
{
  char mask[HOSTMASKLEN];

  _make_mask (mask, target->nick->host, sizeof(mask), 0);
  _push_mode (net, target, mbuf, A_DENIED, 1, mask);
  _push_kick (net, target, mbuf, reason);
}

static void _recheck_modes (net_t *net, link_t *target, userflag rf,
			    userflag cf, modebuf_t *mbuf)
{
  /* check server/channel user's op/voice status to take */
  if ((target->mode & A_ADMIN) &&			/* is an admin */
      ((rf & U_DEOP) ||					/* must be deopped */
       (!(rf & U_MASTER) && (cf & U_DEOP))))
    _push_mode (net, target, mbuf, A_ADMIN, 0, NULL);
  else if ((target->mode & A_OP) &&			/* is an op */
	   ((rf & U_DEOP) ||				/* must be deopped */
	    (!(rf & U_OP) && (cf & U_DEOP))))
    _push_mode (net, target, mbuf, A_OP, 0, NULL);
  else if ((target->mode & A_HALFOP) &&			/* is a halfop */
	   ((rf & U_DEOP) ||				/* must be deopped */
	    (!(rf & U_HALFOP) && (cf & U_DEOP))))
    _push_mode (net, target, mbuf, A_HALFOP, 0, NULL);
  else if ((target->mode & A_VOICE) &&			/* is voiced */
	   (rf & U_QUIET))				/* must be quiet */
    _push_mode (net, target, mbuf, A_VOICE, 0, NULL);
  /* check server/channel user's op/voice status to give */
  if (!(target->mode & A_OP) && !(rf & U_DEOP) && (rf & U_OP) &&
      ((rf & U_AUTO) || (cf & U_OP)))
    _push_mode (net, target, mbuf, A_OP, 1, NULL);	/* autoop */
  else if (!(target->mode & A_HALFOP) && !(rf & U_DEOP) && (rf & U_HALFOP) &&
	   ((rf & U_AUTO) || (cf & U_OP)) &&
	   (net->features & L_HASHALFOP))
    _push_mode (net, target, mbuf, A_HALFOP, 1, NULL);	/* auto-halfop */
  else if (!(target->mode & A_VOICE) && !(rf & U_QUIET) &&
	   ((rf & U_SPEAK) ||
	    ((rf & U_VOICE) && (cf & U_VOICE))))
    _push_mode (net, target, mbuf, A_VOICE, 1, NULL);	/* autovoice */
}

void ircch_recheck_modes (net_t *net, link_t *target, userflag sf, userflag cf,
			  char *info)
{
  link_t *me;
  userflag rf;
  modebuf_t mbuf;

  if (!target || !(me = _find_me_op (net, target->chan)))
    return;		/* I have not any permissions to operate */
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
		    Get_Clientflags (target->chan->chi->name, NULL), &mbuf);
  _flush_mode (net, target->chan, &mbuf);
}

/* do channel mode change parsing, origin may be NULL if it came from server */
int ircch_parse_modeline (net_t *net, ch_t *chan, link_t *origin, char *prefix,
			  userflag uf, bindtable_t *mbt, bindtable_t *kbt,
			  int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
  link_t *me, *target;
  char *pstr, *schr;
  list_t **list;
  binding_t *bind;
  char mf, mc;
  userflag ocf, orf, trf, gcf;
  modeflag mch;
  int nextpar;
  clrec_t *cr;
  char buf[STRING];
  modebuf_t mbuf;

  nextpar = 1;
  me = _find_me_op (net, chan);
  _make_modechars (mbuf.modechars, net);
  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  if (origin)
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
	  if (schr)
	  {
	    if (lc)
	    {
	      lc (buf, schr, sizeof(buf));
	      target = ircch_find_link (net, buf, chan);
	    }
	    else
	      target = ircch_find_link (net, schr, chan);
	  }
      }
      if (mc == mf)
	continue;
      else if (!mf || !list || !mch)
      {
	/* bad modechange! */
	continue;
      }
      snprintf (buf, sizeof(buf), "%s %c%c%s%s", chan->chi->name, mf, mc,
		schr ? " " : "", NONULL(schr));
      for (bind = NULL; (bind = Check_Bindtable (mbt, buf, uf, ocf, bind)); )
      {
	if (bind->name)
	  RunBinding (bind, prefix,
		      (origin && origin->nick->lname) ? origin->nick->lname : "*",
		      chan->chi->name, -1, NextWord (buf));
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
	  list_t *item;

	  if ((item = ircch_find_mask (*list, schr)))
	    ircch_remove_mask (list, item);
	  continue;
	}
	else if (origin)
	{
	  ircch_add_mask (list, origin->nick->host,
			  safe_strlen (origin->nick->name), schr);
	  if ((gcf & U_AUTO) && chan->tid == -1 && /* start enforcer */
	      ((mc == 'b' && mf == '+') || (mc == 'e' && mf == '-')))
	    chan->tid = NewTimer (chan->chi->ift, chan->chi->name, S_LOCAL,
				  ircch_enforcer_time, 0, 0, 0);
	}
	else
	  ircch_add_mask (list, "", 0, schr);
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
	    Set_Field (cr, "passwd", chan->key);
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
	  if (mf == '-')
	    target->mode &= ~mch;
	  else
	    target->mode |= mch;
	  if (!(orf & U_OWNER))		/* owner may change any modes */
	  {
	    trf = _make_rf (net, Get_Clientflags (target->nick->lname, NULL),
			    Get_Clientflags (target->nick->lname, chan->chi->name));
	    _recheck_modes (net, target, trf, gcf, &mbuf);
	  }
	}
	else if (mf == '-')		/* modechange for whole channel */
	{
	  chan->mode &= ~mch;
	}
	else
	{
	  chan->mode |= mch;
	}
      }
    }
  }
  _flush_mode (net, chan, &mbuf);
  return nextpar;
}

void ircch_parse_configmodeline (net_t *net, ch_t *chan, char *mode)
{
  char mf, mc;
  modeflag mch;
  char *c;
  modebuf_t mbuf;

  chan->mlock = chan->munlock = 0;		/* reset it at first */
  _make_modechars (mbuf.modechars, net);
  mf = 0;
  while (*mode)
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
      chan->munlock |= mch;
    else
      chan->mlock |= mch;
  }
}

void ircch_enforcer (net_t *net, ch_t *chan)
{
  link_t *link;
  clrec_t *clr;
  userflag rf, cf;
  list_t *ban, *ex;
  modebuf_t mbuf;

  mbuf.changes = mbuf.pos = mbuf.apos = 0;
  mbuf.cmd = NULL;
  cf = Get_Clientflags (chan->chi->name, NULL);
  for (link = chan->nicks; link; link = link->prevnick)
    if (!(link->mode & (A_ADMIN | A_OP | A_HALFOP)) || !(cf & U_FRIEND))
    {
      if ((clr = Lock_Clientrecord (link->nick->lname)))
      {
	rf = _make_rf (net, Get_Flags (clr, net->neti->name),
		       Get_Flags (clr, chan->chi->name));
	Unlock_Clientrecord (clr);
      }
      else
	rf = 0;
      if (rf & (U_FRIEND | U_MASTER | U_OP | U_HALFOP))
	continue;
      for (ban = chan->bans, ex = NULL; ban; ban = ban->next);
	if (match (ban->what, link->nick->host) > 0)
	{
	  for (ex = chan->exempts; ex; ex = ex->next)
	    if (match (ex->what, ban->what) > 0 &&
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
