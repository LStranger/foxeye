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
 * This file is a part of FoxEye IRCd module: channels management (RFC2811).
 */

#include <foxeye.h>
#if IRCD_USES_ICONV == 0 || (defined(HAVE_ICONV) && (IRCD_NEEDS_TRANSLIT == 0 || defined(HAVE_CYRILLIC_TRANSLIT)))
#include <modules.h>
#include <init.h>
#include <conversion.h>

#include <wchar.h>

#include "ircd.h"
#include "numerics.h"

extern long int _ircd_hold_period;	/* see ircd.c */

static struct bindtable_t *BTIrcdWhochar;
static struct bindtable_t *BTIrcdChannel;
static struct bindtable_t *BTIrcdModechange;
static struct bindtable_t *BTIrcdUmodechange;
static struct bindtable_t *BTIrcdCheckModechange;

ALLOCATABLE_TYPE (CHANNEL, IrcdChan_, users)
ALLOCATABLE_TYPE (MEMBER, IrcdMemb_, prevnick)
ALLOCATABLE_TYPE (MASK, IrcdMask_, next)

/* list of translations MODE char into WHO char - has to be equal lenghts! */
static char *Ircd_modechar_list = "ohvaqO!"; /* list of known '+? nick' modes */
static char *Ircd_whochar_list  = "       "; /* appropriate WHO chars */

static modeflag Ircd_modechar_mask = 0; /* filled with matching to above */

/* these three should have equal size */
static char _ircd_umodes[32]; /* 1 char per modeflag bit */
static char _ircd_cmodes[32]; /* 1 char per modeflag bit */
static char _ircd_wmodes[32]; /* 1 char per modeflag bit */

/* ---------------------------------------------------------------------------
 * Common functions.
 */

#define _ircd_find_channel_lc(ircd,lcname) Find_Key ((ircd)->channels, lcname)

static inline CHANNEL *_ircd_find_channel (IRCD *ircd, const char *name)
{
  char lcname[MB_LEN_MAX*CHANNAMELEN+1];

  unistrlower (lcname, name, sizeof(lcname));
  return _ircd_find_channel_lc (ircd, lcname);
}

#define REPLACE_NEXT_CHANNEL_CHAR {\
  if (*text_replace_char) \
    *ds++ = *text_replace_char; \
  ss++; \
  sz--; \
  continue; }

/* checks if name is valid and replace invalid chars */
static void _ircd_validate_channel_name (char *chname)
{
  /* check name for consistency:
     non-strict: no " \007\r\n,"
     strict: validate to CHARSET_8BIT compatibility */
  size_t sz, sp;
  ssize_t sc;
  wchar_t wc;
  mbstate_t ps;
  char *ds, *ss;
#if IRCD_STRICT_NAMES
  char *os;
  struct conversion_t *conv;
  char namebuf[CHANNAMELEN+1];
#endif

  sz = safe_strlen (chname);
  if (sz == 0)				/* oops! */
    return;
  ds = ss = chname;
#if IRCD_STRICT_NAMES
  conv = Get_Conversion (CHARSET_8BIT);
  os = namebuf;				/* convert to CHARSET_8BIT */
  sp = Undo_Conversion (conv, &os, sizeof(namebuf), chname, sz);
  sz = Do_Conversion (conv, &ss, sz, os, sp); /* convert it back */
  ss[sz] = '\0';			/* terminate the string in any case */
  Free_Conversion (conv); /* ok, we got chname compatible with CHARSET_8BIT */
#endif
  memset(&ps, 0, sizeof(ps)); /* reset the state */
  for (sp = 0; *ss; sp++)
  {
    if (sp > CHANNAMELEN)		/* name is too long */
      break;
    if (strchr ("\007\r\n,", *ss))	/* non-allowed chars */
      REPLACE_NEXT_CHANNEL_CHAR
    sc = mbrtowc (&wc, ss, sz, &ps);
    if (sc <= 0)			/* invalid sequence */
      REPLACE_NEXT_CHANNEL_CHAR
    if (!iswgraph (wc))			/* unprintable character */
    {
      if (*text_replace_char)
	*ds++ = *text_replace_char;
    }
    else				/* copy character */
    {
      if (ds != ss)
	memcpy (ds, ss, sc);
      ds += sc;
    }
    ss += sc;				/* go to next char */
    sz -= sc;
  }
  *ds = '\0';				/* terminate the string */
}

/* creates new empty CHANNEL */
static inline CHANNEL *_ircd_new_channel (IRCD *ircd, const char *name,
					  const char *lcname)
{
  CHANNEL *ch = alloc_CHANNEL();

  strfcpy (ch->name, name, sizeof(ch->name));
  _ircd_validate_channel_name (ch->name);
  strfcpy (ch->lcname, lcname, sizeof(ch->lcname));
  ch->users = ch->creator = ch->invited = NULL;
  ch->count = 0;
  ch->bans = ch->exempts = ch->invites = NULL;
  ch->hold_upto = 0;
  ch->limit = 0;
  ch->fc[0] = *name;
  ch->fc[1] = '\0';
  ch->topic[0] = '\0';
  ch->key[0] = '\0';
  ch->mode = 0;
#if IRCD_MULTICONNECT
  ch->on_ack = 0;
#endif
  if (Insert_Key (&ircd->channels, ch->lcname, ch, 1))
    ERROR("ircd:_ircd_new_channel: tree error on adding %s", ch->lcname);
    //TODO: isn't it fatal?
  return ch;
}

static inline MEMBER *_ircd_is_on_channel (CLIENT *cl, CHANNEL *ch)
{
  register MEMBER *m;

  for (m = ch->users; m; m = m->prevnick)
    if (m->who == cl)
      break;
  return m;
}

/* args: Ircd, buf, umode, sizeof(buf); returns buf */
static inline size_t _ircd_make_Xmode (const char *modeslist, char *buf,
				       modeflag umode, size_t bufsize)
{
  register size_t i, s;
  register modeflag um;

  bufsize--;				/* make a reserve for '\0' */
  for (i = 0, um = 1, s = 0; i < sizeof(_ircd_umodes); i++, um <<= 1)
    if ((umode & um) && modeslist[i])
    {
      buf[s++] = modeslist[i];
      if (s >= bufsize)			/* buffer is filled out */
	break;
    }
  buf[s] = '\0';
  return s;
}

#define _ircd_make_wmode(a,b,c) _ircd_make_Xmode (_ircd_wmodes, a,b,c)
#define _ircd_mode2cmode(a,b,c) _ircd_make_Xmode (_ircd_cmodes, a,b,c)

static inline char *_ircd_make_cmode (char *buf, CHANNEL *ch, size_t bs)
{
  register size_t i;

  i = _ircd_make_Xmode (_ircd_cmodes, buf, ch->mode, bs); /* add bool modes */
  if (i < bs - 3 && ch->limit)		/* reserve for "l X" */
    buf[i++] = 'l';
  if (i < bs - 3 && ch->key[0])		/* reserve for "k X" */
    buf[i++] = 'k';
  if (ch->limit)			/* it's checked above */
    i += snprintf (&buf[i], bs - i, " %hu", ch->limit); /* add limit */
  if (i < bs - 2 && ch->key[0])		/* reserve for " X" */
    snprintf (&buf[i], bs - i, " %s", ch->key); /* add key */
  return buf;
}

static void _ircd_del_from_invited (MEMBER *memb)
{
  register MEMBER **m;

  for (m = &memb->who->via->i.nvited; *m && *m != memb; m = &(*m)->prevchan);
  if (*m)				/* remove channel from user */
    *m = memb->prevchan;
  else
    ERROR ("ircd:ircd_del_from_invited: not found channel %s on %s",
	   memb->chan->name, memb->who->nick);
  for (m = &memb->chan->invited; *m && *m != memb; m = &(*m)->prevnick);
  if (*m)				/* remove user from channel */
    *m = memb->prevnick;
  else
    ERROR ("ircd:ircd_del_from_invited: not found %s on channel %s",
	   memb->who->nick, memb->chan->name);
  free_MEMBER (memb);
}


/* ---------------------------------------------------------------------------
 * Data-independent bindtables.
 */

/* "ircd-whochar" bindings */
BINDING_TYPE_ircd_whochar(iwc_ircd);
static char iwc_ircd (char tc)
{
  switch (tc)
  {
    case 'o':	/* channel operator */
      return '@';
    case 'v':	/* has a voice */
      return '+';
    default:
      return 0;
  }
}

/* Bindings for adding/removing users on different types of channel */
BINDING_TYPE_ircd_channel(ich_normal); /* & and # channels */
static modeflag ich_normal(INTERFACE *u, modeflag umode, modeflag chmode,
			   int count, const char *chname, NODE *cl,
			   const char **tocreate)
{
  if (!tocreate)			/* user parts the channel */
  {
    if (count == 1)
      return 0;				/* destroying the channel */
    return chmode;
  }
  if (!count)				/* doesn't exist yet */
  {
    if (chmode)
      return 0;				/* it's on hold now */
    *tocreate = chname;
    if (*chname == '&')			/* it's local channel */
      return (A_ISON | A_OP | A_INVISIBLE);
    return (A_ISON | A_OP);		/* default mode on creating */
  }
  return A_ISON;			/* default mode for joining */
}

BINDING_TYPE_ircd_channel(ich_add); /* + channels */
static modeflag ich_add(INTERFACE *u, modeflag umode, modeflag chmode,
			int count, const char *chname, NODE *cl,
			const char **tocreate)
{
  if (!tocreate)			/* user parts the channel */
  {
    if (count == 1)
      return 0;				/* destroying the channel */
    return chmode;
  }
  if (!count)				/* doesn't exist yet */
  {
    if (chmode)
      return 0;				/* it's on hold now */
    *tocreate = chname;
  }
  return (A_ISON | A_TOPICLOCK);	/* no-mode channel type */
}

/* checks if !?????name exists and return full name if it does */
static inline const char *_ich_safename_exists (NODE *n, const char *name)
{
  char lcname[MB_LEN_MAX*CHANNAMELEN];
  LEAF *l;
  const char *k;

  unistrlower (lcname, name, sizeof(lcname)); /* lower case part here */
  /* scan whole list for !* channels (it may be slow, I know...) */
  l = Find_Leaf (n, "!", 0);		/* seek to first "!xxx" channel */
  if (!l)				/* there is no '!' channels yet */
    return NULL;
  k = Leaf_Key (l);			/* get key for first found leaf */
  do {
    if (k[0] != '!')			/* no more ! channels */
      return NULL;
    if (!strcmp (lcname, &k[CHIDLEN]))	/* skip id part and compare it */
      return ((CHANNEL *)l->s.data)->name;
    l = Next_Leaf (n, l, &k);		/* get next channel and key */
  } while (l);
  return NULL;
}

#define CHIDCNUM 36		/* number of chars in alphabet below */
static char _ircd_chid_char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

/* makes !?????name in static buffer and returns it */
static inline char *_ich_make_safename (const char *name)
{
  static char nn[MB_LEN_MAX*CHANNAMELEN+1];
  size_t i;
  time_t t = Time;

  nn[0] = '!';				/* start with '!' */
  for (i = 1; i <= CHIDLEN; i++)	/* generate id part */
  {
    nn[i] = _ircd_chid_char[t % CHIDCNUM];
    t /= CHIDCNUM;
  }
  strfcpy (&nn[i], name, sizeof(nn) - 1 - CHIDLEN); /* add name part */
  return nn;
}

BINDING_TYPE_ircd_channel(ich_excl); /* ! channels */
static modeflag ich_excl(INTERFACE *u, modeflag umode, modeflag chmode,
			 int count, const char *chname, NODE *cl,
			 const char **tocreate)
{
  if (!tocreate)			/* user parts the channel */
  {
    if (count == 1)
      return 0;				/* destroying the channel */
    return chmode;
  }
  if (chmode == 0)			/* requested to create */
  {
    if (chname[1] != '!')
    {
      *tocreate = _ich_safename_exists (cl, &chname[1]);
      if (*tocreate)		/* it could be attempt to join by short name */
	return A_ISON;			/* allowed to join found channel */
      return 0;				/* cannot create such way */
    }
    if (chname[2] == '!' || /* creating !<id>! conflicts with joining !<id>! */
	_ich_safename_exists (cl, &chname[2])) /* cannot duplicate short name */
      return 0;
    *tocreate = _ich_make_safename (&chname[2]);
    return (A_ISON | A_OP | A_ADMIN);	/* default mode on creating */
  }
  /* chmode != 0 is OK as there is no 'unavailable' state for safe channels */
  return A_ISON;			/* default mode for joining */
}


/* "ircd-modechange" */

BINDING_TYPE_ircd_modechange(imch_o);
static modeflag imch_o(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (target && ((rchmode & A_OP) || !rchmode))
    return A_OP;
  return 0;
}

BINDING_TYPE_ircd_modechange(imch_v);
static modeflag imch_v(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (target && ((rchmode & A_OP) || !rchmode))
    return A_VOICE;
  return 0;
}

BINDING_TYPE_ircd_modechange(imch_a);
static modeflag imch_a(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && !rchmode) /* it's testing */
    return A_ANONYMOUS;
  if (target || !(rchmode & A_OP))
    return 0;
  if (chtype == '&')			/* & channel */
    return A_ANONYMOUS;
  if (chtype == '!' && (rchmode && A_ADMIN) && add) /* creator on ! channel */
    return A_ANONYMOUS;
  return A_PINGED; /* mark of ERR_UNIQOPPRIVSNEEDED */
}

BINDING_TYPE_ircd_modechange(imch_i);
static modeflag imch_i(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && ((rchmode & A_OP) || !rchmode))
    return A_INVITEONLY;
  return 0;
}

BINDING_TYPE_ircd_modechange(imch_m);
static modeflag imch_m(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && ((rchmode & A_OP) || !rchmode))
    return A_MODERATED;
  return 0;
}

BINDING_TYPE_ircd_modechange(imch_n);
static modeflag imch_n(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && ((rchmode & A_OP) || !rchmode))
    return A_NOOUTSIDE;
  return 0;
}

BINDING_TYPE_ircd_modechange(imch_q);
static modeflag imch_q(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && !rchmode) /* it's testing */
    return A_QUIET;
  return 0;				/* immutable */
}

BINDING_TYPE_ircd_modechange(imch_p);
static modeflag imch_p(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && !rchmode) /* it's testing */
    return A_PRIVATE;
  if (!target && (rchmode & A_OP) && !(tmode & A_SECRET))
    return A_PRIVATE;
  return 0;
}

BINDING_TYPE_ircd_modechange(imch_s);
static modeflag imch_s(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && !rchmode) /* it's testing */
    return A_SECRET;
  if (!target && (rchmode & A_OP) && !(tmode & A_PRIVATE))
    return A_SECRET;
  return 0;
}

BINDING_TYPE_ircd_modechange(imch_r);
static modeflag imch_r(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && !rchmode) /* it's testing */
    return A_REOP;
  if (!target && chtype == '!' && (rchmode & A_ADMIN)) /* creator on ! channel */
    return A_REOP;
  return A_PINGED; /* mark of ERR_UNIQOPPRIVSNEEDED */
}

BINDING_TYPE_ircd_modechange(imch_t);
static modeflag imch_t(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && ((rchmode & A_OP) || !rchmode))
    return A_TOPICLOCK;
  return 0;
}

/* this is used to pass channel ptr on call of _imch_do_* functions */
static CHANNEL *_imch_channel;
/* this is used to make sending numerics faster in _imch_do_* */
static CLIENT *_imch_client;

static int _imch_do_keyset (INTERFACE *srv, const char *rq, const char *ch,
			    int add, const char *param)
{
  if (add < 0)
    return 0; /* invalid query */
  else if (add)
    //TODO: limit its length?
    //TODO: ERR_KEYSET
    strfcpy (_imch_channel->key, param, sizeof(_imch_channel->key));
  else
    _imch_channel->key[0] = '\0';
  return 1;
}

BINDING_TYPE_ircd_modechange(imch_k);
static modeflag imch_k(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && (rchmode & A_OP))
  {
    *ma = &_imch_do_keyset;
    return (A_KEYSET | (add ? 1 : 0));
  }
  return (add ? 1 : 0);
}

static int _imch_do_limit (INTERFACE *srv, const char *rq, const char *ch,
			   int add, const char *param)
{
  if (add < 0)
    return 0; /* invalid query */
  else if (add)
    _imch_channel->limit = atoi (param);
  else
    _imch_channel->limit = 0;
  return 1;
}

BINDING_TYPE_ircd_modechange(imch_l);
static modeflag imch_l(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && (rchmode & A_OP))
  {
    *ma = &_imch_do_limit;
    return (A_LIMIT | (add ? 1 : 0));
  }
  return (add ? 1 : 0);
}

static int _imch_add_mask (MASK **list, const char *mask)
{
  register MASK *mm;
  MASK *nm;

  if (simple_match ("*!*@*", mask) < 2) /* sanity check */
    return 0;
  nm = alloc_MASK();
  unistrlower (nm->what, mask, sizeof(nm->what));
  /* note: it might exceed field size? */
  mask = nm->what;
  while (*list)
    if (simple_match (mask, (*list)->what) > 0) /* it eats that one */
    {
      mm = *list;
      *list = mm->next;
      free_MASK (mm);
    }
    else if (simple_match ((*list)->what, mask) > 0) /* that one eats it */
    {
      free_MASK (nm);
      return 0;
    }
    else
      list = &(*list)->next;
  *list = nm;
  nm->next = NULL;
  return 1; /* done */
}

static int _imch_del_mask (MASK **list, const char *mask)
{
  register MASK *mm;
  char what[HOSTMASKLEN+1];

  unistrlower (what, mask, sizeof(what));
  while ((mm = *list))
    if (!strcmp (mm->what, what))
    {
      *list = mm->next;
      free_MASK (mm);
      return 1; /* done */
    }
    else
      list = &mm->next;
  return 0; /* not found */
}

static int _imch_do_banset (INTERFACE *srv, const char *rq, const char *ch,
			    int add, const char *param)
{
  if (add < 0)				/* query ban list */
  {
    MASK *m;

    for (m = _imch_channel->bans; m; m = m->next)
      ircd_do_cnumeric (_imch_client, RPL_BANLIST, _imch_channel, 0, m->what);
    ircd_do_unumeric (_imch_client, RPL_ENDOFBANLIST, _imch_client, 0, NULL);
    return 1;
  }
  else if (add)
    return _imch_add_mask (&_imch_channel->bans, param);
  else
    return _imch_del_mask (&_imch_channel->bans, param);
}

BINDING_TYPE_ircd_modechange(imch_b);
static modeflag imch_b(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && ((rchmode & A_OP) || add < 0))
  {
    *ma = &_imch_do_banset;
    return (A_DENIED | 1);
  }
  return 1;
}

static int _imch_do_exemptset (INTERFACE *srv, const char *rq, const char *ch,
			       int add, const char *param)
{
  if (add < 0)				/* query exempts list */
  {
    MASK *m;

    for (m = _imch_channel->exempts; m; m = m->next)
      ircd_do_cnumeric (_imch_client, RPL_EXCEPTLIST, _imch_channel, 0, m->what);
    ircd_do_unumeric (_imch_client, RPL_ENDOFEXCEPTLIST, _imch_client, 0, NULL);
    return 1;
  }
  else if (add)
    return _imch_add_mask (&_imch_channel->exempts, param);
  else
    return _imch_del_mask (&_imch_channel->exempts, param);
}

BINDING_TYPE_ircd_modechange(imch_e);
static modeflag imch_e(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && ((rchmode & A_OP) || add < 0))
  {
    *ma = &_imch_do_exemptset;
    return (A_EXEMPT | 1);
  }
  return 1;
}

static int _imch_do_inviteset (INTERFACE *srv, const char *rq, const char *ch,
			       int add, const char *param)
{
  if (add < 0)				/* query invite list */
  {
    MASK *m;

    for (m = _imch_channel->invites; m; m = m->next)
      ircd_do_cnumeric (_imch_client, RPL_INVITELIST, _imch_channel, 0, m->what);
    ircd_do_unumeric (_imch_client, RPL_ENDOFINVITELIST, _imch_client, 0, NULL);
    return 1;
  }
  else if (add)
    return _imch_add_mask (&_imch_channel->invites, param);
  else
    return _imch_del_mask (&_imch_channel->invites, param);
}

BINDING_TYPE_ircd_modechange(imch_I);
static modeflag imch_I(INTERFACE *srv, const char *rq, modeflag rchmode,
		       const char *target, modeflag tmode, int add, char chtype,
		       int (**ma)(INTERFACE *, const char *, const char *, int,
				  const char *))
{
  if (!target && (rchmode & A_OP) && (tmode & A_INVITEONLY))
  {
    *ma = &_imch_do_inviteset;
    return (A_INVITED | 1);
  }
  return 1;
}


/* "ircd-umodechange" */
BINDING_TYPE_ircd_umodechange(iumch_a);
static modeflag iumch_a(INTERFACE *srv, const char *rq, modeflag rumode,
			int add)
{
  if (!rumode) /* it's a test */
    return A_AWAY;
  return 0;
}

BINDING_TYPE_ircd_umodechange(iumch_i);
static modeflag iumch_i(INTERFACE *srv, const char *rq, modeflag rumode,
			int add)
{
  return A_INVISIBLE;
}

BINDING_TYPE_ircd_umodechange(iumch_w);
static modeflag iumch_w(INTERFACE *srv, const char *rq, modeflag rumode,
			int add)
{
  return A_WALLOP;
}

BINDING_TYPE_ircd_umodechange(iumch_r);
static modeflag iumch_r(INTERFACE *srv, const char *rq, modeflag rumode,
			int add)
{
  if (add || !rumode) /* cannot be removed */
    return A_RESTRICTED;
  return 0;
}

BINDING_TYPE_ircd_umodechange(iumch_o);
static modeflag iumch_o(INTERFACE *srv, const char *rq, modeflag rumode,
			int add)
{
  if (!add || /* only can be deopped */
      !rumode || /* or it's a test */
      (rumode & A_SERVER)) /* or servermode */
    return A_OP;
  return 0;
}

BINDING_TYPE_ircd_umodechange(iumch_O);
static modeflag iumch_O(INTERFACE *srv, const char *rq, modeflag rumode,
			int add)
{
  if (!add || /* only can be deopped */
      !rumode || /* or it's a test */
      (rumode & A_SERVER)) /* or servermode */
    return A_HALFOP;
  return 0;
}

BINDING_TYPE_ircd_umodechange(iumch_s);
static modeflag iumch_s(INTERFACE *srv, const char *rq, modeflag rumode,
			int add)
{
  return 0; /* not supported, obsolete flag */
}


/* restricted users cannot change any modes */
BINDING_TYPE_ircd_check_modechange(ichmch_r);
static int ichmch_r(modeflag umode, modeflag mmode, int add, modeflag chg, char *tgt)
{
  if (umode & A_RESTRICTED)
    return 0;
  return 1;
}


/* ---------------------------------------------------------------------------
 * Data manipulation bindtables.
 */

static inline void _ircd_mode_broadcast (IRCD *ircd, int id, CLIENT *sender,
					 CHANNEL *ch, char *imp,
					 char *modepass, const char **passed,
					 int x)
{
  ssize_t sz;
  int i;
  char buff[MESSAGEMAX];

  if (*imp != '+' && *imp != '-')	/* no empty signs */
    imp++;
  *imp = '\0';				/* terminate line */
  sz = sizeof(buff);
  buff[0] = 0;				/* in case if no arguments */
  for (i = 0; i < x && sz > 0; i++)	/* compose arguments */
    sz -= snprintf (buff, sz, " %s", passed[i]);
    //TODO: errors check?
  /* notify local users who are on channel */
  if (CLIENT_IS_SERVER (sender))
    ircd_sendto_chan_local (ch, ":%s MODE %s %s%s", sender->nick, ch->name,
			    modepass, buff);
  else if (CLIENT_IS_SERVICE (sender))	/* it's forbidden for local services */
    ircd_sendto_chan_local (ch, ":%s@%s MODE %s %s%s", sender->nick,
			    sender->cs->nick, ch->name, modepass, buff);
  else
    ircd_sendto_chan_local (ch, ":%s!%s@%s MODE %s %s%s", sender->nick,
			    sender->user, sender->host, ch->name, modepass,
			    buff);
#ifdef USE_SERVICES
  //TODO: notify local services too
#endif
  /* every server should know channel state too */
  imp = strchr (ch->name, ':');	/* use it as mask ptr storage */
  if (imp)
  {
    imp++;
#if IRCD_MULTICONNECT
    if (id >= 0) {
      ircd_sendto_servers_mask_new(ircd, NULL, imp, ":%s IMODE %d %s %s%s",
				   sender->nick, id, ch->name, modepass, buff);
      ircd_sendto_servers_mask_old(ircd, NULL, imp, ":%s MODE %s %s%s",
				   sender->nick, ch->name, modepass, buff);
    } else
#endif
      ircd_sendto_servers_mask(ircd, NULL, imp, ":%s MODE %s %s%s",
			       sender->nick, ch->name, modepass, buff);
  }
  else
#if IRCD_MULTICONNECT
    if (id >= 0) {
      ircd_sendto_servers_new(ircd, NULL, ":%s IMODE %d %s %s%s",
			      sender->nick, id, ch->name, modepass, buff);
      ircd_sendto_servers_old(ircd, NULL, ":%s MODE %s %s%s",
			      sender->nick, ch->name, modepass, buff);
    } else
#endif
      ircd_sendto_servers_all(ircd, NULL, ":%s MODE %s %s%s",
			      sender->nick, ch->name, modepass, buff);
}

/* few MODE specific sub-functions */
static inline int _ircd_mode_query_reply (CLIENT *cl, CHANNEL *ch)
{
  char cmode[KEYLEN+64]; /* A-Za-z num key */
  register MEMBER *memb;

  memb = _ircd_is_on_channel (cl, ch);
  if (!memb)
    return ircd_do_cnumeric (cl, ERR_USERNOTINCHANNEL, ch, 0, cl->nick);
  if (ch->name[0] == '+')		/* nomode channel */
    return ircd_do_cnumeric (cl, ERR_NOCHANMODES, ch, 0, NULL);
  if (ch->creator)
    ircd_do_cnumeric (cl, RPL_UNIQOPIS, ch, 0, ch->creator->who->nick);
  _ircd_make_cmode (cmode, ch, sizeof(cmode));
  return ircd_do_cnumeric (cl, RPL_CHANNELMODEIS, ch, 0, cmode);
}

static inline int _ircd_mode_mask_query_reply (INTERFACE *srv, CLIENT *cl,
					CHANNEL *ch, const char *par, modeflag mm)
{
  modeflag mf;
#define static register
  BINDING_TYPE_ircd_modechange ((*f));
#undef static
  int (*ma)(INTERFACE *, const char *, const char *, int, const char *);
  register struct binding_t *b;

  if (ch->name[0] == '+')		/* nomode channel */
    return ircd_do_cnumeric (cl, ERR_NOCHANMODES, ch, 0, NULL);
  b = Check_Bindtable (BTIrcdModechange, par, U_ALL, U_ANYCH, NULL);
  ma = NULL;
  if (!b || b->name || b->key[1] != '*') /* check for parameterized */
    return ircd_do_cnumeric (cl, ERR_UNKNOWNMODE, ch, 0, par);
  f = (void *)b->func;		/* run binding */
  if (!(mf = f (srv, cl->nick, mm, NULL, ch->mode, -1, ch->name[0], &ma)) ||
      !ma)
    return ircd_do_cnumeric (cl, ERR_CHANOPRIVSNEEDED, ch, 0, NULL);
  ma (srv, cl->nick, ch->name, -1, NULL); /* do report */
  return 1;
}

#define CONTINUE_ON_MODE_ERROR(A,B) do { \
    ircd_do_cnumeric (cl, A, ch, 0, B); \
    continue; } while(0)

BINDING_TYPE_ircd_client_cmd(ircd_mode_cb); /* huge one as hell */
static int ircd_mode_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			char *host, int argc, const char **argv)
{ /* args: <target> [modes...] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  CHANNEL *ch;
  int i, n;
  char modepass[2*MAXMODES+1];

  if (argc < 1)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  ch = _ircd_find_channel ((IRCD *)srv->data, argv[0]);
  if (ch == NULL && ircd_find_client (argv[0], NULL) != cl)
    return ircd_do_unumeric (cl, ERR_USERSDONTMATCH, cl, 0, argv[0]);
  if (ch)				/* channel mode request */
  {
    MEMBER *memb;
    char *imp;
    const char *passed[MAXMODES];
    int x;

    if (argc == 1)			/* channel mode query */
      return _ircd_mode_query_reply (cl, ch);
    memb = _ircd_is_on_channel (cl, ch); /* may query some modes if NULL */
    _imch_channel = ch;
    _imch_client = cl;
    if (argc == 2 && *argv[1] != '+' && *argv[1] != '-') /* mask mode query */
      return _ircd_mode_mask_query_reply (srv, cl, ch, argv[1],
					  memb ? memb->mode : 0);
    if (!memb)
      return ircd_do_cnumeric (cl, ERR_USERNOTINCHANNEL, ch, 0, peer->dname);
    if (ch->name[0] == '+')		/* nomode channel */
      return ircd_do_cnumeric (cl, ERR_NOCHANMODES, ch, 0, NULL);
    n = x = 0;
    imp = modepass;
    *imp = 0;
    for (i = 1; i < argc; i++)		/* parse modes */
    {
      const char *c;
      int add = -1;

      for (c = argv[i]; *c; c++)
      {
	if (*c == '+')			/* adding mode */
	{
	  if (imp > modepass && *imp != '-' && *imp != '+')
	    imp++;
	  *imp = *c;
	  add = 1;
	}
	else if (*c == '-')		/* removing mode */
	{
	  if (imp > modepass && *imp != '-' && *imp != '+')
	    imp++;
	  *imp = *c;
	  add = 0;
	}
	else if (add < 0)		/* invalid */
	{
	  char charstr[2];

	  charstr[0] = *c;
	  charstr[1] = '\0';
	  ircd_do_cnumeric (cl, ERR_UNKNOWNMODE, ch, 0, charstr);
	}
	else				/* valid */
	{
	  struct binding_t *b;
	  modeflag mf = 0;
	  char charstr[2];
#define static register
	  BINDING_TYPE_ircd_modechange ((*f));
#undef static
	  int (*ma)(INTERFACE *, const char *, const char *, int, const char *);
	  const char *par = NULL;
	  MEMBER *tar;

	  charstr[0] = *c;
	  charstr[1] = '\0';
	  b = Check_Bindtable (BTIrcdModechange, charstr, U_ALL, U_ANYCH, NULL);
	  if (!b)
	    CONTINUE_ON_MODE_ERROR (ERR_UNKNOWNMODE, charstr);
	  tar = NULL;
	  if ((par = strchr (Ircd_modechar_list, *c)) /* check for compliance */
	      && Ircd_whochar_list[par-Ircd_modechar_list] == ' ')
	  {
	    if (i + 1 >= argc)		/* if param available at all */
	      CONTINUE_ON_MODE_ERROR (ERR_NEEDMOREPARAMS, NULL);
	    par = argv[++i];		/* target is next param */
	    tar = _ircd_is_on_channel (ircd_find_client (par, NULL), ch);
	    if (!tar)
	      CONTINUE_ON_MODE_ERROR (ERR_USERNOTINCHANNEL, NULL);
	  }
	  while (b)			/* cycle thru all */
	  {
	    if (!b->name)
	    {
	      f = (void *)b->func;
	      if (tar)			/* modechange for target */
		mf |= f (srv, peer->dname, memb->mode, tar->who->nick,
			 tar->mode, add, ch->name[0], &ma);
	      else
		mf |= f (srv, peer->dname, memb->mode, NULL, ch->mode, add,
			 ch->name[0], &ma);
	    }
	    b = Check_Bindtable (BTIrcdModechange, charstr, U_ALL, U_ANYCH, b);
	  }
	  if (mf & 1)			/* require a parameter */
	  {
	    if (i + 1 >= argc)		/* but parameter unavailable */
	      CONTINUE_ON_MODE_ERROR (ERR_NEEDMOREPARAMS, NULL);
	    par = argv[++i];		/* parameter is next one */
	    mf--;			/* reset the flag */
	  }
	  if (mf & A_PINGED)		/* check if A_ADMIN required but not */
	    CONTINUE_ON_MODE_ERROR (ERR_UNIQOPPRIVSNEEDED, NULL);
	  while (mf && (b = Check_Bindtable (BTIrcdCheckModechange, peer->dname,
					     U_ALL, U_ANYCH, b)))
	    if (!b->name && !b->func (memb->mode, ch->mode, mf, add, tar))
	      mf = 0;			/* change denied, stop */
	  if (!mf)			/* check permissions */
	    CONTINUE_ON_MODE_ERROR (ERR_CHANOPRIVSNEEDED, NULL);
	  if (n == MAXMODES)
	    continue; //TODO: silently ignore or what?
	  n++;				/* one more accepted */
	  if (add)
	  {
	    if (tar) {			/* it has a target */
	      tar->mode |= mf;
	      if (mf & A_OP)		/* operator added so reset this */
		ch->noop_since = 0;
	    } else if (par) {		/* it has a parameter */
	      if (ma (srv, peer->dname, ch->name, add, par))
		ch->mode |= mf;
	      else
		WARNING ("ircd: error on setting MODE %s +%c %s", ch->name, *c,
			 par);
	    } else			/* just modechange */
	      ch->mode |= mf;
	    *++imp = *c;		/* it has '+' or last */
	    if (par)
	      passed[x++] = par;	/* one more param accepted */
	    continue;
	  }
	  if (tar)			/* it has a target */
	    tar->mode &= ~mf;
	    //TODO: need we set noop_since on MODE #chan -o nick ?
	  else if (par)			/* it has a parameter */
	  {
	    if (ma (srv, peer->dname, ch->name, add, par))
	      ch->mode &= ~mf;
	    else
	      WARNING ("ircd: error on setting MODE %s -%c %s", ch->name, *c,
		       par);
	  }
	  else				/* just modechange */
	    ch->mode &= ~mf;
	  *++imp = *c;			/* it has '-' or last */
	  if (par)
	    passed[x++] = par;		/* one more param accepted */
	}
      }
    }
    if (n)				/* there were some changes */
      _ircd_mode_broadcast((IRCD *)srv->data, ircd_new_id(), cl, ch, imp,
			   modepass, passed, x);
  }
  else					/* umode request */
  {
    modeflag toadd = 0, todel = 0;

    if (argc == 1)			/* umode query */
    {
      char umode[16];
      ircd_make_umode (umode, cl->umode, sizeof(umode));
      return ircd_do_unumeric (cl, RPL_UMODEIS, cl, 0, umode);
    }
    n = 0;
    for (i = 1; i < argc; i++)		/* parse modes */
    {
      const char *c;
      int add = -1;

      for (c = argv[i]; *c; c++)
      {
	if (*c == '+')			/* adding */
	  add = 1;
	else if (*c == '-')		/* removing */
	  add = 0;
	else if (add < 0)		/* invalid */
	{
	  char charstr[2];

	  charstr[0] = *c;
	  charstr[1] = '\0';
	  ircd_do_unumeric (cl, ERR_UMODEUNKNOWNFLAG, cl, 0, charstr);
	}
	else if (n == MAXMODES)
	  ; //TODO: silently ignore or what?
	else				/* valid */
	{
	  struct binding_t *b;
	  modeflag mf = 0;
	  char charstr[2];
#define static register
	  BINDING_TYPE_ircd_umodechange ((*f));
#undef static

	  charstr[0] = *c;
	  charstr[1] = '\0';
	  b = Check_Bindtable (BTIrcdUmodechange, charstr, U_ALL, U_ANYCH, NULL);
	  if (!b)
	  {
	    ircd_do_unumeric (cl, ERR_UMODEUNKNOWNFLAG, cl, 0, charstr);
	    continue;			/* ignoring it */
	  }
	  while (b)			/* cycle thru all */
	  {
	    if (!b->name)
	      mf |= (f = (void *)b->func) (srv, peer->dname, cl->umode, add);
	    b = Check_Bindtable (BTIrcdUmodechange, charstr, U_ALL, U_ANYCH, b);
	  }
	  while (mf && (b = Check_Bindtable (BTIrcdCheckModechange, peer->dname,
					     U_ALL, U_ANYCH, b)))
	    if (!b->name && !b->func (cl->umode, peer->dname, mf, add))
	      mf = 0;			/* change denied, stop */
	  if (!mf)
	    continue;			/* change denied */
	  if (add)
	  {
	    mf &= ~cl->umode;		/* reset modes that we have already */
	    if (!mf)
	      continue;
	    n++;			/* one more accepted */
	    New_Request (cl->via->p.iface, 0, "MODE %s +%c", peer->dname, *c);
	    toadd |= mf;
	    todel &= ~mf;
	    continue;
	  }
	  mf &= cl->umode;		/* reset modes that we don't have */
	  if (!mf)
	    continue;
	  n++;				/* one more accepted */
	  New_Request (cl->via->p.iface, 0, "MODE %s -%c", peer->dname, *c);
	  todel |= mf;
	  toadd &= ~mf;
	}
      }
    }
    toadd &= ~A_HALFOP;			/* localops should not be broadcasted */
    todel &= ~A_HALFOP;
    if (toadd | todel)			/* we have something changed */
    {
      char *c = modepass;

      if (toadd)
      {
	*c++ = '+';
	ircd_make_umode (c, toadd, MAXMODES+1);
	c += strlen (c);
      }
      if (todel)
      {
	*c++ = '-';
	ircd_make_umode (c, todel, MAXMODES+1);
      }
#ifdef USE_SERVICES
      //TODO: notify local services too
#endif
      ircd_sendto_servers_new (((IRCD *)srv->data), NULL, ":%s IMODE %d %s %s",
			       peer->dname, ircd_new_id(), peer->dname,
			       modepass);
      ircd_sendto_servers_old (((IRCD *)srv->data), NULL, ":%s MODE %s %s",
			       peer->dname, peer->dname, modepass);
    }
  }
  return 1;
}
#undef CONTINUE_ON_MODE_ERROR

/* modified version of ircd_new_to_channel() */
static inline MEMBER *_ircd_do_join(IRCD *ircd, CLIENT *cl, CHANNEL *ch,
				    const char *name, modeflag mf)
{
  MEMBER *r;
  register MEMBER *mm;

  if (!ch)
  {
    char lcname[MB_LEN_MAX*CHANNAMELEN+1];

    unistrlower (lcname, name, sizeof(lcname));
    _ircd_validate_channel_name (lcname);
    ch = _ircd_find_channel_lc (ircd, lcname); /* last check for the name */
    if (!ch)				/* it may comply after validation */
      ch = _ircd_new_channel (ircd, name, lcname);
  }
  for (mm = ch->invited; mm; mm = mm->prevnick)
    if (mm->who == cl)
      break;
  if (mm)
    _ircd_del_from_invited (mm);
  r = ircd_add_to_channel (ircd, NULL, ch, cl, mf); /* this way cannot get errors */
  if (ch->topic[0])
    ircd_do_cnumeric (cl, RPL_TOPIC, ch, 0, ch->topic);
  else
    ircd_do_cnumeric (cl, RPL_NOTOPIC, ch, 0, NULL);
  ircd_names_reply (ircd_find_client(NULL, NULL), cl, ch, 0); /* RPL_NAMREPLY */
  ircd_do_unumeric (cl, RPL_ENDOFNAMES, cl, 0, ch->name);
  return (r);
}

static inline void _ircd_join_0_local (IRCD *ircd, CLIENT *cl, char *key)
{
  register CHANNEL *ch;

  if (key == NULL)
    key = cl->nick;
  while (cl->c.hannels)
  {
    if ((ch = cl->c.hannels->chan)->mode & A_QUIET)
      New_Request (cl->via->p.iface, 0, ":%s!%s@%s PART %s :%s", cl->nick,
		   cl->user, cl->host, ch->name, key);
    else if (ch->mode & A_ANONYMOUS)
    {
      New_Request (cl->via->p.iface, 0, ":%s!%s@%s PART %s :%s", cl->nick,
		   cl->user, cl->host, ch->name, key);
      ircd_sendto_chan_butone (ch, cl->c.hannels, ":anonymous!anonymous@anonymous. PART %s :anonymous",
			       ch->name);
    }
    else
      ircd_sendto_chan_local (ch, ":%s!%s@%s PART %s :%s", cl->nick,
			      cl->user, cl->host, ch->name, key);
#ifdef USE_SERVICES
    //TODO: inform services
#endif
    ircd_del_from_channel (ircd, cl->c.hannels, 0);
  }
  ircd_sendto_servers_all_ack(ircd, cl, CHANNEL0, (struct peer_priv *)NULL,
			      ":%s JOIN 0 :%s", cl->nick, key);
}

BINDING_TYPE_ircd_client_cmd(ircd_join_cb);
static int ircd_join_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			char *host, int argc, const char **argv)
{ /* args: <channel> [,<channel> ...] [<key> [,<key> ... ]] | 0 */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  CHANNEL *ch;
  register MEMBER *mm;
  char *chn, *key, *nextch, *nextkey, *cmask;
  const char *nchn;
  CLIENT *me = ircd_find_client(NULL, NULL);
  struct binding_t *b;
#define static register
  BINDING_TYPE_ircd_channel ((*f));
  BINDING_TYPE_ircd_check_modechange ((*ff));
#undef static
  MASK *cm;
  modeflag mf;
  int n = 0, x, i, ptr;
  char cnfc[2];
  char lcb[MB_LEN_MAX*NICKLEN+USERLEN+HOSTLEN+3];
  char bufforservers[MB_LEN_MAX*IRCMSGLEN];

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
#ifdef USE_SERVICES
  //TODO: forbid for services
#endif
  chn = (char *)argv[0];
  nextkey = NULL;
  if (argc == 1)
    key = NULL;
  else
    key = (char *)argv[1];
  for (x = 0, mm = cl->c.hannels; mm; mm = mm->prevchan) /* count channels */
    x++;
  cnfc[1] = '\0';
  ptr = 0;
  while (chn)
  {
    /* split with next chan */
    nextch = strchr (chn, ',');
    if (nextch)
      *nextch++ = 0;
    if (key)
      nextkey = strchr (key, ',');
    if (nextkey)
      *nextkey++ = 0;
    if (!strcmp (chn, "0"))		/* user requested to part all */
    {
      _ircd_join_0_local ((IRCD *)srv->data, cl, key);
      chn = nextch;
      key = nextkey;
      x = 0;
      continue;
    }
    //TODO: just drop ^G or cancel (sub)join?
    cmask = strchr (chn, ':');
    if (cmask)
      cmask++;
    /* now we have chn, cmask, and key prepared so check them */
    i = 0;
    mf = 0;
    cnfc[0] = chn[0];
    lcb[0] = '\0';
    ch = _ircd_find_channel ((IRCD *)srv->data, chn);
    if (ch && Time > ch->hold_upto &&	/* it's available to hold off now */
	ch->count == 0)
    {
      ircd_drop_channel ((IRCD *)srv->data, ch);
      ch = NULL;
    }
    nchn = NULL;
    if (cmask && simple_match (cmask, me->lcnick) <= 0)
      i = -ircd_do_unumeric (cl, ERR_BADCHANMASK, cl, 0, cmask);
    else if ((b = Check_Bindtable (BTIrcdChannel, cnfc, U_ALL, U_ANYCH, NULL))
	     && !b->name)
      mf = (f = (void *)b->func) (peer->iface, cl->umode, ch ? ch->mode : 0,
				  ch ? ch->count : 0, chn,
				  ((IRCD *)srv->data)->channels, &nchn);
    if (ch && !mf)			/* channel is still on hold */
      ircd_do_unumeric (cl, ERR_UNAVAILRESOURCE, cl, 0, chn);
    else if (!mf)			/* cannot create a channel */
      ircd_do_unumeric (cl, ERR_NOSUCHCHANNEL, cl, 0, chn);
    else if (!ch)			/* OK, user is allowed to create */
      i = 1;
    else if (cl->umode & A_OP)		/* IRCop can override some modes */
      i = 1;
    else if (ch->limit && ch->count >= ch->limit) /* out of channel limit */
      ircd_do_cnumeric (cl, ERR_CHANNELISFULL, ch, 0, NULL);
    else if (ch->key[0] && strcmp (ch->key, key)) /* check key */
      ircd_do_cnumeric (cl, ERR_BADCHANNELKEY, ch, 0, NULL);
    else if (ch->mode & A_INVITEONLY)	/* check invitations */
    {
      for (mm = ch->invited; mm; mm = mm->prevnick)
	if (mm->who == cl)
	  break;			/* found */
      if (!mm)
      {
	snprintf (lcb, sizeof(lcb), "%s!%s@%s", cl->lcnick, cl->user, cl->host);
	for (cm = ch->invites; cm; cm = cm->next)
	  if (simple_match (cm->what, lcb) > 0) //TODO: check expiration
	    break;
	if (!cm)			/* not found */
	  i = -ircd_do_cnumeric (cl, ERR_INVITEONLYCHAN, ch, 0, NULL);
      }
    }
    if (mf && i == 0)			/* check bans/exceptions */
    {
      for (mm = ch->invited; mm; mm = mm->prevnick)
	if (mm->who == cl)
	  break;
      if (!mm)				/* found invite will override ban */
      {
	if (!*lcb)			/* it might be done by check above */
	  snprintf (lcb, sizeof(lcb), "%s!%s@%s", cl->lcnick, cl->user, cl->host);
	for (cm = ch->bans; cm; cm = cm->next)
	  if (simple_match (cm->what, lcb) > 0)
	    break;			/* found ban */
	if (cm)
	{
	  for (cm = ch->exempts; cm; cm = cm->next)
	    if (simple_match (cm->what, lcb) > 0)
	      break;			/* found exception */
	  if (!cm)
	    i = -ircd_do_cnumeric (cl, ERR_BANNEDFROMCHAN, ch, 0, NULL);
	}
      }
    }
    if (mf && i == 0)			/* OK, user is allowed to join yet */
    {
      b = NULL;
      while ((b = Check_Bindtable (BTIrcdCheckModechange, ch->name, U_ALL,
				   U_ANYCH, b)))
	if (!b->name && (ff = (void *)b->func) (cl->umode, mf, 1, 0, NULL) == 0)
	  break;			/* denied! */
      if (!b)
	i = 1;				/* so he/she allowed at last */
    }
    if (n++ >= MAXJOINS)		/* bad arguments list */
      ircd_do_unumeric (cl, ERR_TOOMANYTARGETS, cl, 0, "Join aborted.");
    else if (x++ >= MAXCHANNELS)	/* joined too many channels already */
      ircd_do_unumeric (cl, ERR_TOOMANYCHANNELS, cl, 0, NULL);
    else if (i > 0) {			/* so user can join, do it then */
      mm = _ircd_do_join ((IRCD *)srv->data, cl, ch, nchn, mf);
      if (!(ch->mode & A_INVISIBLE)) {	/* it is not a local channel */
	char smode[sizeof(Ircd_modechar_list)+1];

	_ircd_make_wmode(smode, mm->mode, sizeof(smode));
	if (cmask == NULL) {		/* global wide channel */
	  if (ptr && ptr + strlen(ch->name) >= sizeof(bufforservers) - 2) {
	    ircd_sendto_servers_all((IRCD *)srv->data, NULL, ":%s JOIN %s",
				    cl->nick, bufforservers);
	    ptr = 0;
	  }
	  ptr += snprintf(bufforservers, sizeof(bufforservers) - ptr, "%s%s%s%s",
			  ptr ? "," : "", ch->name, *smode ? "" : "\007", smode);
	} else				/* there is a channel mask */
	  ircd_sendto_servers_mask((IRCD *)srv->data, NULL, cmask,
				   ":%s JOIN %s%c%s", cl->nick, ch->name,
				   *smode ? '\0' : '\007', smode);
      }
    }
    chn = nextch;
    key = nextkey;
  }
  if (ptr)
    ircd_sendto_servers_all((IRCD *)srv->data, NULL, ":%s JOIN %s", cl->nick,
			    bufforservers);
  return 1;
}

#define _ircd_find_client_lc(I,X) Find_Key ((I)->clients, X)

#define MAXTRACKED_MODE_ERRORS 4

/* this one should be used in brackets if around if() */
#define CONTINUE_ON_MODE_ERROR(A,B,...) \
    ERROR ("ircd:" A B, __VA_ARGS__); \
    if (errors < MAXTRACKED_MODE_ERRORS) \
      lasterror[errors] = A; \
    errors++; \
    continue

#undef __TRANSIT__
#define __TRANSIT__ __CHECK_TRANSIT__(token)
/* huge function, used by both ircd_mode_sb and ircd_imode */
static int _ircd_do_smode(INTERFACE *srv, struct peer_priv *pp,
			  unsigned short token, int id, const char *sender,
			  const char *lcsender, char *cmd, int argc,
			  const char **argv)
{ /* input: <channel> modes... */
  CLIENT *src, *tgt;
  CHANNEL *ch;
  int i, n;
  char modepass[2*MAXMODES+1];

  if (!(src = _ircd_find_client_lc ((IRCD *)srv->data, lcsender)))
  {
    ERROR ("ircd:MODE command by unknown \"%s\" via %s", sender, pp->p.dname);
    return ircd_recover_done (pp, "bogus MODE sender");
  }
  ch = _ircd_find_channel ((IRCD *)srv->data, argv[0]);
  if (ch)				/* channel mode change */
  {
    register MEMBER *who;
    char *imp;
    const char *lasterror[MAXTRACKED_MODE_ERRORS];
    modeflag whof;
    const char *passed[MAXMODES];
    int x, errors;

    _imch_channel = ch;
    _imch_client = src;
    if (ch->name[0] == '+')		/* nomode channel */
    {
      ERROR ("ircd:MODE for no-mode %s via %s", ch->name, pp->p.dname);
      return ircd_recover_done (pp, "MODE for modeless channel");
    } else if (ch->mode & A_INVISIBLE) { /* local channel */
      ERROR ("ircd:MODE for local %s via %s", ch->name, pp->p.dname);
      return ircd_recover_done (pp, "MODE for local channel");
    }
    if (CLIENT_IS_SERVER(src))
      whof = A_OP | A_ADMIN;		/* for servermode */
    else if ((who = _ircd_is_on_channel (src, ch)))
      whof = who->mode;
    else
    {
      ERROR ("ircd:MODE by %s not on %s via %s", src->nick, ch->name,
	     pp->p.dname);
      if (!ircd_recover_done (pp, "bogus MODE sender"))
	return 1;
      whof = A_OP | A_ADMIN;		/* but allow it anyway */
    }
    n = x = errors = 0;
    imp = modepass;
    *imp = 0;
    for (i = 1; i < argc; i++)		/* parse modes */
    {
      const char *c;
      int add = -1;

      for (c = argv[i]; *c; c++)
      {
	if (*c == '+')			/* adding mode */
	{
	  if (imp > modepass && *imp != '-' && *imp != '+')
	    imp++;
	  *imp = *c;
	  add = 1;
	}
	else if (*c == '-')		/* removing mode */
	{
	  if (imp > modepass && *imp != '-' && *imp != '+')
	    imp++;
	  *imp = *c;
	  add = 0;
	}
	else if (add < 0) {		/* invalid */
	  CONTINUE_ON_MODE_ERROR ("unknown MODE char", " %c via %s", *c,
				  pp->p.dname);
	} else {			/* valid */
	  struct binding_t *b;
	  modeflag mf = 0;
	  char charstr[2];
#define static register
	  BINDING_TYPE_ircd_modechange ((*f));
#undef static
	  int (*ma)(INTERFACE *, const char *, const char *, int, const char *);
	  const char *par = NULL;
	  MEMBER *tar;

	  charstr[0] = *c;
	  charstr[1] = '\0';
	  b = Check_Bindtable (BTIrcdModechange, charstr, U_ALL, U_ANYCH, NULL);
	  if (!b) {
	    /* cannot revert it since don't know if it should take parameter
	       and also it may mess order but what we can do anyway? squit? */
	    CONTINUE_ON_MODE_ERROR ("unknown MODE char", " %c via %s", *c,
				    pp->p.dname);
	  }
	  tar = NULL;
	  if ((par = strchr (Ircd_modechar_list, *c)) /* check for compliance */
	      && Ircd_whochar_list[par-Ircd_modechar_list] != ' ')
	  {
	    if (i + 1 >= argc) {	/* if param available at all */
	      CONTINUE_ON_MODE_ERROR ("incomplete MODE", " %c%c via %s",
				      add ? '+' : '-', *c, pp->p.dname);
	    }
	    par = argv[++i];		/* target is next param */
	    tar = _ircd_is_on_channel (ircd_find_client (par, pp), ch);
	    /* ircd_find_client() traces history for nick changes so
	       there should be no race collisions for MODE on that nick */
	    if (!tar) {
	      CONTINUE_ON_MODE_ERROR ("bogus MODE target", " %s not on %s via %s",
				      par, ch->name, pp->p.dname);
	    }
	  }
	  while (b)			/* cycle thru all */
	  {
	    if (!b->name)
	    {
	      f = (void *)b->func;
	      if (tar)			/* modechange for target */
		mf |= f (srv, pp->p.dname, whof, tar->who->nick,
			 tar->mode, add, ch->name[0], &ma);
	      else
		mf |= f (srv, pp->p.dname, whof, NULL, ch->mode, add,
			 ch->name[0], &ma);
	    }
	    b = Check_Bindtable (BTIrcdModechange, charstr, U_ALL, U_ANYCH, b);
	  }
	  if (mf & 1)			/* require a parameter */
	  {
	    if (i + 1 >= argc) {	/* but parameter unavailable */
	      CONTINUE_ON_MODE_ERROR ("incomplete MODE", " %c%c via %s",
				      add ? '+' : '-', *c, pp->p.dname);
	    }
	    par = argv[++i];		/* parameter is next one */
	    mf--;			/* reset the flag */
	  }
	  mf &= ~A_PINGED;		/* reset extra flag */
	  while (mf && (b = Check_Bindtable (BTIrcdCheckModechange, pp->p.dname,
					     U_ALL, U_ANYCH, b)))
	    if (!b->name && !b->func (whof, ch->mode, mf, add, tar))
	      mf = 0;			/* change denied, stop */
	  if (!mf)			/* check permissions */
	  {
	    New_Request (pp->p.iface, 0, "MODE %s %c%c %s", ch->name,
			 add ? '-' : '+', *c, NONULL(par)); /* revert it */
	    CONTINUE_ON_MODE_ERROR ("impossible MODE", " %c%c via %s",
				    add ? '+' : '-', *c, pp->p.dname);
	  }
	  if (n == MAXMODES)
	  {
#if IRCD_MULTICONNECT
	    if (id >= 0) {
	      ERROR("ircd:too many modes via %s, squit it to avoid desync",
		    pp->p.dname);
	      errors = -1;
	      i = argc;			/* terminate parsing right now */
	      break;
	    }
#endif
	    _ircd_mode_broadcast ((IRCD *)srv->data, -1, src, ch, imp, modepass,
				  passed, x);
	    n = x = 0;
	    imp = modepass;
	    if (add)
	      *imp = '+';
	    else
	      *imp = '-';
	  }
	  n++;				/* one more accepted */
	  if (add)
	  {
	    if (tar) {			/* it has a target */
	      tar->mode |= mf;
	      if (mf & A_OP)		/* operator added so reset this */
		ch->noop_since = 0;
	    } else if (par) {		/* it has a parameter */
	      if (ma (srv, pp->p.dname, ch->name, add, par))
		ch->mode |= mf;
	      else
		WARNING ("ircd: error on setting MODE %s +%c %s", ch->name, *c,
			 par);
	    } else			/* just modechange */
	      ch->mode |= mf;
	    *++imp = *c;		/* it has '+' or last */
	    if (par)
	      passed[x++] = par;	/* one more param accepted */
	    continue;
	  }
	  if (tar)			/* it has a target */
	    tar->mode &= ~mf;
	    //TODO: need we set noop_since on MODE #chan -o nick ?
	  else if (par)			/* it has a parameter */
	  {
	    if (ma (srv, pp->p.dname, ch->name, add, par))
	      ch->mode &= ~mf;
	    else
	      WARNING ("ircd: error on setting MODE %s -%c %s", ch->name, *c,
		       par);
	  }
	  else				/* just modechange */
	    ch->mode &= ~mf;
	  *++imp = *c;			/* it has '-' or last */
	  if (par)
	    passed[x++] = par;		/* one more param accepted */
	}
      }
    }
    if (n)				/* there were some changes */
      _ircd_mode_broadcast ((IRCD *)srv->data, id, src, ch, imp, modepass,
			    passed, x);
#if IRCD_MULTICONNECT
    if (errors < 0)
      ircd_do_squit(pp->link, pp, "MODE protocol error");
    else
#endif
      for (i = 0; i < errors; i++)
	if (!ircd_recover_done (pp, (i >= MAXTRACKED_MODE_ERRORS) ?
						"MODE error" : lasterror[i]))
	  break; /* return */
  }
  else if ((tgt = ircd_find_client(argv[0], pp)) != NULL &&
	   !tgt->hold_upto)		/* user mode */
  {
    modeflag toadd = 0, todel = 0;
    const char *lasterror[MAXTRACKED_MODE_ERRORS];
    int errors;

    n = errors = 0;
    for (i = 1; i < argc; i++)		/* parse modes */
    {
      const char *c;
      int add = -1;

      for (c = argv[i]; *c; c++)
      {
	if (*c == '+')			/* adding */
	  add = 1;
	else if (*c == '-')		/* removing */
	  add = 0;
	else if (add < 0)		/* invalid */
	{
	  ERROR ("ircd:unknown MODE char %c for %s via %s", *c, tgt->nick,
		 pp->p.dname);
	  if (!ircd_recover_done (pp->p.iface->data, "unknown MODE char"))
	    return 1;
	}
	else				/* valid */
	{
	  struct binding_t *b;
	  modeflag mf = 0;
	  char charstr[2];
#define static register
	  BINDING_TYPE_ircd_umodechange ((*f));
#undef static

	  charstr[0] = *c;
	  charstr[1] = '\0';
	  b = Check_Bindtable (BTIrcdUmodechange, charstr, U_ALL, U_ANYCH, NULL);
	  if (!b)
	  {
	    New_Request (pp->p.iface, 0, "MODE %s %c%c", tgt->nick,
			 add ? '-' : '+', *c); /* revert it */
	    CONTINUE_ON_MODE_ERROR ("unknown MODE char", " %c for %s via %s",
				    *c, tgt->nick, pp->p.dname);
	  }
	  while (b)			/* cycle thru all */
	  {
	    if (!b->name)
	      mf |= (f = (void *)b->func) (srv, pp->p.dname, src->umode, add);
	    b = Check_Bindtable (BTIrcdUmodechange, charstr, U_ALL, U_ANYCH, b);
	  }
	  if (!mf)
	  {
	    New_Request (pp->p.iface, 0, "MODE %s %c%c", tgt->nick,
			 add ? '-' : '+', *c); /* revert it */
	    CONTINUE_ON_MODE_ERROR ("impossible MODE", " %s %c%c via %s",
				    tgt->nick, add ? '+' : '-', *c,
				    pp->p.dname);
	  }
	  if (mf & A_HALFOP) {		/* remote cannot switch localop flag */
	    CONTINUE_ON_MODE_ERROR ("impossible MODE", " %s %c%c via %s",
				    tgt->nick, add ? '+' : '-', *c,
				    pp->p.dname);
	  }
	  if (add)
	  {
	    mf &= ~tgt->umode;		/* reset modes that we have already */
	    if (!mf)
	      continue;
	    n++;			/* one more accepted */
	    New_Request (tgt->via->p.iface, 0, "MODE %s +%c", tgt->nick, *c);
	    toadd |= mf;
	    todel &= ~mf;
	    continue;
	  }
	  mf &= tgt->umode;		/* reset modes that we don't have */
	  if (!mf)
	    continue;
	  n++;				/* one more accepted */
	  New_Request (tgt->via->p.iface, 0, "MODE %s -%c", tgt->nick, *c);
	  todel |= mf;
	  toadd &= ~mf;
	}
      }
    }
    if (toadd | todel)			/* we have something changed */
    {
      char *c = modepass;

      if (toadd)
      {
	*c++ = '+';
	ircd_make_umode (c, toadd, MAXMODES+1);
	c += strlen (c);
      }
      if (todel)
      {
	*c++ = '-';
	ircd_make_umode (c, todel, MAXMODES+1);
      }
#ifdef USE_SERVICES
      //TODO: notify local services too
#endif
#if IRCD_MULTICONNECT
      if (id >= 0) {
	ircd_sendto_servers_new(((IRCD *)srv->data), NULL, ":%s IMODE %d %s %s",
				sender, id, pp->p.dname, modepass);
	ircd_sendto_servers_old(((IRCD *)srv->data), NULL, ":%s MODE %s %s",
				sender, pp->p.dname, modepass);
      } else
#endif
	ircd_sendto_servers_all(((IRCD *)srv->data), NULL, ":%s MODE %s %s",
				sender, pp->p.dname, modepass);
    }
    for (i = 0; i < errors; i++)
      if (!ircd_recover_done (pp, (i >= MAXTRACKED_MODE_ERRORS) ?
						"MODE error" : lasterror[i]))
	break; /* return */
  }
  else					/* unrecognized target */
  {
    ERROR ("ircd:MODE command for unknown \"%s\" via %s", argv[0], pp->p.dname);
    ircd_recover_done (pp->p.iface->data, "bogus MODE target");
  }
  return 1;
}

BINDING_TYPE_ircd_server_cmd(ircd_mode_sb);
static int ircd_mode_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender, char *cmd,
			int argc, const char **argv)
{ /* args: <target> modes... */
  struct peer_priv *pp = peer->iface->data; /* it's really peer */

  if (argc < 2)
  {
    ERROR ("ircd:incomplete MODE command by %s via %s", sender, peer->dname);
    return ircd_recover_done (pp, "incomplete MODE command");
  }
  return _ircd_do_smode(srv, pp, token, -1, sender, lcsender, cmd, argc, argv);
}

#if IRCD_MULTICONNECT
BINDING_TYPE_ircd_server_cmd(ircd_imode);
static int ircd_imode(INTERFACE *srv, struct peer_t *peer, unsigned short token,
		      const char *sender, const char *lcsender, char *cmd,
		      int argc, const char **argv)
{ /* args: <id> <target> modes... */
  struct peer_priv *pp = peer->iface->data; /* it's really peer */
  int id;

  if (!(pp->link->cl->umode & A_MULTI))
    return (0);			/* it is ambiguous from RFC2813 servers */
  if (argc < 3) {
    ERROR ("ircd:incomplete IMODE command by %s via %s", sender, peer->dname);
    return ircd_recover_done (pp, "incomplete MODE command");
  }
  id = atoi(argv[0]);
  if (!ircd_test_id(((IRCD *)srv->data)->token[token], id))
    //TODO: log duplicate?
    return (1);
  return _ircd_do_smode(srv, pp, token, id, sender, lcsender, cmd, argc - 1,
			&argv[1]);
}
#endif /* IRCD_MULTICONNECT */
#undef __TRANSIT__
#define __TRANSIT__

#undef CONTINUE_ON_MODE_ERROR


/* ---------------------------------------------------------------------------
 * Logging facility.
 */

#define _IRCD_LOGGER_STEP 8

typedef struct {
  CHANNEL *m;
  flag_t fl;
} __ircd_logger;

static __ircd_logger *_ircd_internal_logger_list = NULL;
static int _ircd_internal_logger_list_n = 0;
static int _ircd_internal_logger_list_a = 0;

static INTERFACE *_ircd_internal_logger = NULL;
static IRCD *_ircd_internal_logger_ircd;

/* system channels */
static CLIENT ME = { .umode = A_ISON, .via = NULL, .c.hannels = NULL };

static int _ircd_internal_logger_req (INTERFACE *i, REQUEST *req)
{
  if (req)
  {
    int i;
    register __ircd_logger *log;

    for (i = 0; i < _ircd_internal_logger_list_n; i++)
      if ((log = &_ircd_internal_logger_list[i])->fl & req->flag)
	ircd_sendto_chan_local (log->m, ":%s NOTICE %s :%s",
				req->from->name, log->m->name, req->string);
  }
  return REQ_OK;
}

static iftype_t _ircd_internal_logger_sig (INTERFACE *i, ifsig_t sig)
{
  if (sig == S_TERMINATE && i)
  {
    while (ME.c.hannels)
      ircd_del_from_channel (_ircd_internal_logger_ircd, ME.c.hannels, 0);
    FREE (&_ircd_internal_logger_list);
    _ircd_internal_logger_list_a = _ircd_internal_logger_list_n = 0;
    i->ift = I_DIED;
  }
  return 0;
}

static void _ircd_log_channel (IRCD *ircd, const char *name, flag_t fl)
{
  MEMBER *memb;
  register __ircd_logger *log;

  /* create channel and add ME to it */
  DBG("adding system channel %s", name);
  memb = ircd_new_to_channel (ircd, NULL, name, &ME,
			      A_INVISIBLE | A_MODERATED | A_TOPICLOCK |
			      A_QUIET | A_ANONYMOUS | A_NOOUTSIDE);
  if (!memb)
  {
    ERROR ("ircd:duplicate _ircd_log_channel for %s", name);
    return;
  }
  //add it into logger array
  if (!_ircd_internal_logger)
  {
    _ircd_internal_logger_ircd = ircd;
    _ircd_internal_logger = Add_Iface (I_LOG, "*", &_ircd_internal_logger_sig,
				       &_ircd_internal_logger_req, NULL);
  }
  if (_ircd_internal_logger_list_a == _ircd_internal_logger_list_n)
  {
    _ircd_internal_logger_list_a += _IRCD_LOGGER_STEP;
    safe_realloc ((void **)&_ircd_internal_logger_list,
		  _ircd_internal_logger_list_a * sizeof(__ircd_logger));
  }
  log = &_ircd_internal_logger_list[_ircd_internal_logger_list_n++];
  log->m = memb->chan;
  log->fl = fl;
}


/* ---------------------------------------------------------------------------
 * Common external functions.
 */

/* returns whochar for first appropriate mode within Ircd_modechar_list */
char ircd_mode2whochar (modeflag mf)
{
  if (mf & Ircd_modechar_mask)
  {
    char wm[16];
    register char ch;
    int i;

    _ircd_make_wmode (wm, mf, sizeof(wm)); /* make list of modes of mf */
    for (i = 0; (ch = Ircd_modechar_list[i]); i++) /* scan Ircd_modechar_list */
      if (Ircd_whochar_list[i] != ' ')	/* if it's supported */
	if (strchr (wm, ch))		/* and present in mf */
	  return Ircd_whochar_list[i];	/* then return whochar */
  }
  return ' ';
}

/* adds to existing channel and does local broadcast */
MEMBER *ircd_add_to_channel (IRCD *ircd, struct peer_priv *bysrv, CHANNEL *ch,
			     CLIENT *cl, modeflag mf)
{
  MEMBER *memb;
  CLIENT *server;
  size_t sz;
  int i, n;
  modeflag modeadd;
  char smode[sizeof(Ircd_modechar_list)+1];
  char madd[MESSAGEMAX];

  if (!ch || !cl)
  {
    DBG ("ircd:ircd_add_to_channel: %p to %p: NULL!", cl, ch);
    return NULL;
  }
#if IRCD_MULTICONNECT
  if (bysrv && ircd_check_ack(bysrv, cl, ch))
    return NULL;			/* duplicate, ignoring */
  if (bysrv && ircd_check_ack(bysrv, cl, CHANNEL0))
    return NULL;			/* we sent JOIN 0, ignoring */
#endif
  if (_ircd_is_on_channel (cl, ch))
  {
    DBG ("ircd:ircd_add_to_channel: %s already is on %s!", cl->nick, ch->name);
    return NULL;
  }
  if ((mf & A_ADMIN) && ch->creator)	/* another creator? abort it */
  {
    ERROR ("ircd: attempt to set %s as creator of %s while there was another one %s",
	   cl->nick, ch->name, ch->creator->who->nick);
    if (bysrv)
      if (!ircd_recover_done (bysrv, "duplicate channel creator"))
	return NULL; /* it could squit it of course */
    mf &= ~A_ADMIN;
  }
  memb = alloc_MEMBER();		/* set new MEMBER */
  memb->who = cl;
  memb->chan = ch;
  memb->mode = A_ISON | (mf & Ircd_modechar_mask);
  memb->prevchan = cl->c.hannels;
  memb->prevnick = ch->users;
  cl->c.hannels = memb;
  ch->users = memb;
  ch->count++;
  if (mf & A_ADMIN)			/* support for ! channels */
    ch->creator = memb;
  modeadd = (mf & ~(A_ISON | Ircd_modechar_mask | ch->mode));
  ch->mode |= A_ISON | (mf & ~Ircd_modechar_mask);
  if (memb->mode & A_OP)		/* operator added so reset this */
    ch->noop_since = 0;
  if (!(ch->mode & A_QUIET))		/* notify users */
  {
    if(ch->mode & A_ANONYMOUS)
    {
      if (!CLIENT_IS_ME(cl) && CLIENT_IS_LOCAL(cl))
	New_Request (cl->via->p.iface, 0, ":%s!%s@%s JOIN %s", cl->nick,
		     cl->user, cl->host, ch->name);
      ircd_sendto_chan_butone (ch, memb, ":anonymous!anonymous@anonymous. JOIN %s",
			       ch->name); /* broadcast for users */
    }
    else
    {
      _ircd_make_wmode (smode, memb->mode, sizeof(smode)); /* mode chars */
      for (i = 0, n = strlen (smode), sz = 0; i < n && sz < sizeof(madd)-3; i++)
      {
	madd[sz++] = ' ';
	sz += strfcpy (madd, cl->nick, sizeof(madd) - sz); /* add " nick" there */
      }
      ircd_sendto_chan_local (ch, ":%s!%s@%s JOIN %s", cl->nick, cl->user,
			      cl->host, ch->name); /* broadcast for users */
      if (bysrv)
	server = bysrv->link->cl;
      else
	server = ircd_find_client(NULL, NULL);
      if (*smode)			/* we have a mode provided */
	ircd_sendto_chan_local(ch, ":%s MODE %s +%s%s", server->lcnick,
			       cl->nick, smode, madd);
      madd[0] = 0;
      if (modeadd)			/* it is a fresh channel or updated */
	_ircd_mode2cmode (madd, modeadd, sizeof(madd)); /* make channel mode */
      if (madd[0])
	ircd_sendto_chan_local(ch, ":%s MODE %s +%s", server->lcnick,
			       ch->name, madd);
    }
#ifdef USE_SERVICES
    //inform services!
#endif
  }
  else if (!CLIENT_IS_ME(cl) && CLIENT_IS_LOCAL(cl)) /* notify only sender */
    New_Request (cl->via->p.iface, 0, ":%s!%s@%s JOIN %s", cl->nick, cl->user,
		 cl->host, ch->name);
  return memb;
}

/* simply adds a client to channel, does not checks anything */
MEMBER *ircd_new_to_channel (IRCD *ircd, struct peer_priv *bysrv, const char *name,
			     CLIENT *cl, modeflag mf)
{
  char lcname[MB_LEN_MAX*CHANNAMELEN+1];
  CHANNEL *ch;
  register MEMBER *memb;

  unistrlower (lcname, name, sizeof(lcname));
  _ircd_validate_channel_name (lcname);
  ch = _ircd_find_channel_lc (ircd, lcname);
  if (!ch)
    ch = _ircd_new_channel (ircd, name, lcname);
#if IRCD_MULTICONNECT
  if (!ch->name[0])			/* channel was hold by acks */
  {
    strfcpy (ch->name, name, sizeof(ch->name)); /* update name now */
    _ircd_validate_channel_name (ch->name);
    ch->mode = 0;			/* see ircd_del_from_channel() */
    Add_Request (I_LOG, "*", F_WARN,	/* send warning */
		 "ircd: got an user %s to holded channel %s (%s)", cl->nick,
		 ch->name, name);
  }
#endif
  memb = ircd_add_to_channel (ircd, bysrv, ch, cl, mf);
  if (!ch->mode) /* fresh empty channel should be removed */
    ircd_drop_channel (ircd, ch);
  return memb;
}

#define CLEAR_MASKS(a) for (; (x = a); free_MASK (x)) a = x->next

/* removes MEMBER, runs bindings, should be called after broadcast */
void ircd_del_from_channel (IRCD *ircd, MEMBER *memb, int tohold)
{
  register MEMBER **m;
#define static register
  BINDING_TYPE_ircd_channel ((*f));
#undef static

  if (memb == memb->chan->creator)	/* support for ! channels */
    memb->chan->creator = NULL;
  for (m = &memb->who->c.hannels; *m && *m != memb; m = &(*m)->prevchan);
  if (*m)				/* remove channel from user */
    *m = memb->prevchan;
  else
    ERROR ("ircd:ircd_del_from_channel: not found channel %s on %s",
	   memb->chan->name, memb->who->nick);
  for (m = &memb->chan->users; *m && *m != memb; m = &(*m)->prevnick);
  if (*m)				/* remove user from channel */
  {
    modeflag mf;
    register struct binding_t *b;

    *m = memb->prevnick;
    if (memb->mode & A_OP) {		/* check if it was last OP left */
      register MEMBER *op;

      for (op = memb->chan->users; op; op = op->prevnick)
	if (op->mode & A_OP)
	  break;
      if (op)
	op->chan->noop_since = Time;
    }
    if (tohold) {			/* it's split, mark it now! */
      if (memb->chan->name[0] == '!')	/* special support for safe channels */
	memb->chan->hold_upto = Time + _ircd_hold_period;
      else
	memb->chan->hold_upto = memb->chan->noop_since + _ircd_hold_period;
    }
    mf = 0;				/* in case of unknown type */
    b = Check_Bindtable (BTIrcdChannel, memb->chan->fc, U_ALL, U_ANYCH, NULL);
    if (b && !b->name)			/* run internal binding */
    {
      register INTERFACE *u;

      f = (void *)b->func;
      if (CLIENT_IS_ME (memb->who))
	u = NULL;
      if (CLIENT_IS_LOCAL (memb->who))
	u = memb->who->via->p.iface;
      else
	u = NULL;
      mf = f (u, memb->who->umode, memb->chan->mode, memb->chan->count,
	      memb->chan->name, ircd->channels, NULL);
    }
    //TODO: check if channel mode was changed and there are local users left
    if ((--memb->chan->count) == 0 && mf == 0 && /* want to delete channel */
	Time > memb->chan->hold_upto)
    {
      MASK *x;

      CLEAR_MASKS (memb->chan->bans);
      CLEAR_MASKS (memb->chan->exempts);
      CLEAR_MASKS (memb->chan->invites);
#if IRCD_MULTICONNECT
      memb->chan->name[0] = '\0';	/* mark it for later */
      if (memb->chan->on_ack)
	memb->chan->hold_upto = Time;	/* hold it while acks on it */
      else
#endif
	ircd_drop_channel (ircd, memb->chan);
    }
    else
      memb->chan->mode = mf;
  }
  else
    ERROR ("ircd:ircd_del_from_channel: not found %s on channel %s",
	   memb->who->nick, memb->chan->name);
  free_MEMBER (memb);
}

MEMBER *ircd_find_member (IRCD *ircd, const char *chan, CLIENT *client)
{
  register CHANNEL *ch = _ircd_find_channel (ircd, chan);
  register CLIENT *cl;
  register MEMBER *m;

  if (!ch)
    return NOSUCHCHANNEL;
  if (!(cl = client))
    return ch->users;
  for (m = ch->users; m; m = m->prevnick)
    if (m->who == cl)
      return m;
  return NULL;
}

void ircd_add_invited (CLIENT *cl, CHANNEL *ch)
{
  register MEMBER *memb;

  if (CLIENT_IS_ME(cl) || !CLIENT_IS_LOCAL (cl))
    return;
  for (memb = ch->invited; memb; memb = memb->prevnick)
    if (memb->who == cl)
      return;
  memb = alloc_MEMBER();
  memb->who = cl;
  memb->chan = ch;
  memb->prevchan = cl->via->i.nvited;
  memb->prevnick = ch->invited;
  cl->via->i.nvited = memb;
  ch->invited = memb;
}

/* removes user from channel and marks I_PENDING for further notify */
void ircd_quit_all_channels (IRCD *ircd, CLIENT *cl, int tohold, int isquit)
{
  register MEMBER *td;
  MEMBER *ch;

  /* do it with anonymous channels at first and send PART to local users */
  if (isquit)
    for (ch = cl->c.hannels; ch; ch = ch->prevchan)
      if (ch->chan->mode & A_ANONYMOUS)
      {
	for (td = ch->chan->users; td; td = td->prevnick) /* ignore cl and me */
	  if (td != ch && !CLIENT_IS_ME(td->who) && CLIENT_IS_LOCAL (td->who))
	    td->who->via->p.iface->ift |= I_PENDING; /* it needs notify */
	Add_Request (I_PENDING, "*", 0, /* PART instead of QUIT, RFC2811 */
		     ":anonymous!anonymous@anonymous. PART %s :anonymous",
		     ch->chan->name);
      }
  /* and now work with non-anonymous and non-quiet channels, mark them */
  for (ch = cl->c.hannels; ch; ch = ch->prevchan)
    if (!(td->chan->mode & (A_ANONYMOUS | A_QUIET)))
      for (td = ch->chan->users; td; td = td->prevnick)
	if (td != ch && !CLIENT_IS_ME(td->who) && CLIENT_IS_LOCAL (td->who))
	  td->who->via->p.iface->ift |= I_PENDING; /* it needs notify */
  /* remove from list of invited too */
  if (!CLIENT_IS_ME(td->who) && CLIENT_IS_LOCAL(cl))
    while (cl->via->i.nvited)
      _ircd_del_from_invited (cl->via->i.nvited);
  if (!isquit)
    return;
  /* and at last remove user from channels */
  while (cl->c.hannels)
    ircd_del_from_channel (ircd, cl->c.hannels, tohold); /* remove from list */
}

/* removes channel structure which was on hold, it should have no acks ATM */
void ircd_drop_channel (IRCD *ircd, CHANNEL *ch)
{
  register MASK *x;

  dprint (4, "ircd:ircd_drop_channel %s", ch->lcname); /* ch->name undefined */
  if (ch->count || ch->users)
    ERROR ("ircd:ircd_drop_channel: count=%d, users=%p", ch->count, ch->users);
  CLEAR_MASKS (ch->bans);
  CLEAR_MASKS (ch->exempts);
  CLEAR_MASKS (ch->invites);
  while (ch->invited)
    _ircd_del_from_invited (ch->invited);
  if (Delete_Key (ircd->channels, ch->lcname, ch))
    ERROR("ircd:ircd_drop_channel: tree error on removing %s", ch->lcname);
    //TODO: isn't it fatal?
  free_CHANNEL (ch);
}

#define IRCD_SET_MODECHAR(f,s,c) \
if (f) do { \
  register modeflag mf = 1; \
  register size_t shift = 0; \
  while (mf && shift < sizeof(s)) \
    if (f & mf) { \
      s[shift] = c; \
      break; } \
    else { \
      shift++; \
      mf <<= 1; } } while(0)

/* internal sub-functions */
static inline char *_ircd_ch_flush_umodes (INTERFACE *i, char *c, char *e)
{
  modeflag mode;
  struct binding_t *b;
#define static register
  BINDING_TYPE_ircd_umodechange ((*ff));
#undef static

  if (!(b = Check_Bindtable (BTIrcdUmodechange, c, U_ALL, U_ANYCH, NULL)) ||
      b->name)
    return c;
  ff = (void *)b->func;
  mode = ff (i, NULL, 0, 0);
  IRCD_SET_MODECHAR (mode, _ircd_umodes, *c);
  if (c < e)
    c++;
  return c;
}

static inline char *_ircd_ch_flush_cmodes (INTERFACE *i, char *c, char *e)
{
  Function dummy;
  modeflag mode;
  struct binding_t *b;
#define static register
  BINDING_TYPE_ircd_modechange ((*ff));
#undef static

  if (!(b = Check_Bindtable (BTIrcdModechange, c, U_ALL, U_ANYCH, NULL)) ||
      b->name)
    return c;
  ff = (void *)b->func;		/* make _ircd_cmodes */
  mode = ff (i, NULL, 0, NULL, 0, 0, '\0', &dummy);
  IRCD_SET_MODECHAR (mode, _ircd_cmodes, *c);
  ff = (void *)b->func;		/* make Ircd_modechar_mask */
  mode = ff (i, NULL, 0, "", 0, 0, '\0', &dummy);
  Ircd_modechar_mask |= mode;
  IRCD_SET_MODECHAR (mode, _ircd_wmodes, *c);
  if (c < e)
    c++;
  return c;
}

/* updates strings for fast access */
void ircd_channels_flush (IRCD *ircd, char *modestring, size_t s)
{
  int i;
  struct binding_t *b = NULL;
  char ch;
  char *c, *e;
#define static
  BINDING_TYPE_ircd_whochar ((*f));
#undef static

  for (i = 0; Ircd_modechar_list[i]; i++)
    Ircd_whochar_list[i] = ' ';		/* clear list of channel whochars */
  while ((b = Check_Bindtable (BTIrcdWhochar, ircd->iface->name, U_ALL,
			       U_ANYCH, b)))
    if (!b->name) /* do internal only */
      for (i = 0; Ircd_modechar_list[i]; i++)
	if ((ch = (f = (void *)b->func) (Ircd_modechar_list[i])))
	  Ircd_whochar_list[i] = ch;	/* update list of channel whochars */
  /* make modes for 004 - including 'O' hidden mode for ! channels */
  memset (_ircd_umodes, 0, sizeof(_ircd_umodes));
  c = modestring;
  e = &c[s-1];
  for (ch = 'a'; ch <= 'z'; ch++)	/* do user modes */
  {
    *c = ch;
    c[1] = 0;
    c = _ircd_ch_flush_umodes (ircd->iface, c, e);
    *c = ch - 'a' + 'A'; /* uppercase one */
    c[1] = 0;
    c = _ircd_ch_flush_umodes (ircd->iface, c, e);
  }
  memset (_ircd_cmodes, 0, sizeof(_ircd_cmodes));
  memset (_ircd_wmodes, 0, sizeof(_ircd_wmodes));
  Ircd_modechar_mask = A_ADMIN;		/* 'O' is present */
  if (c < e)
    *c++ = ' '; /* space between user modes and channel modes */
  if (c <= e) for (ch = 'a'; ch <= 'z'; ch++) /* do channel modes */
  {
    *c = ch;
    c[1] = 0;
    c = _ircd_ch_flush_cmodes (ircd->iface, c, e);
    *c = ch - 'a' + 'A'; /* uppercase one */
    c[1] = 0;
    if (ch == 'o') /* 'O' matches in any case */
    {
      if (c < e)
	c++;
    }
    else
      c = _ircd_ch_flush_cmodes (ircd->iface, c, e);
  }
  *c = '\0'; /* terminate the string */
}

#define FILL_BUFFER(What,Char) \
    for (mask = ch->What; mask; mask = mask->next) \
    { \
      size_t k = strlen (mask->what); \
      if (t + k + l + s > IRCMSGLEN - 4 || /* reserving mode char and space */\
	  l >= MAXMODES) \
      { \
	New_Request (to, 0, "%.*s%s", t + l, buff, &buff[t + MAXMODES + 1]); \
	l = s = 0; \
      } \
      buff[t + l] = Char; \
      l++; \
      buff[t + MAXMODES + 1 + s] = ' '; /* " a!b@c" */ \
      strfcpy (&buff[t + MAXMODES + 2 + s], mask->what, k + 1); \
      s += (k + 1); \
    }

void ircd_burst_channels (INTERFACE *to, NODE *channels)
{
  LEAF *leaf = NULL;
  CHANNEL *ch;
  MEMBER *m;
  MASK *mask;
  size_t s, l, t;
  char buff[MB_LEN_MAX*IRCMSGLEN+1];

  while ((leaf = Next_Leaf (channels, leaf, NULL)))
  {
    ch = leaf->s.data;
    if (ch->hold_upto)			/* it's unavailable */
      continue;
    m = ch->users;
    while (m)				/* do NJOIN */
    {
      l = snprintf (buff, sizeof(buff), "NJOIN %s", ch->name); /* start size */
      while (m)
      {
	t = strlen (m->who->nick) + 3;	/* projected size */
	s = unistrcut (buff, sizeof(buff) - t, IRCMSGLEN - 2 - t); /* a room */
	if (s <= l)			/* insufficient space */
	  break;
	if (m->mode & A_ADMIN)		/* creator */
	  s = snprintf (&buff[l], sizeof(buff) - l, " @@%s", m->who->nick);
	else
	  s = snprintf (&buff[l], sizeof(buff) - l, " %c%s",
			ircd_mode2whochar (m->mode), m->who->nick);
	l += s;
	m = m->prevnick;
      }
      New_Request (to, 0, "%s", buff);
    }
    if (ch->mode != A_ISON || ch->limit || ch->key[0]) /* do not-mask modes */
    {
      _ircd_make_cmode (buff, ch, sizeof(buff));
      New_Request (to, 0, "MODE %s +%s", ch->name, buff);
    }
    l = s = 0;				/* do masks */
    t = snprintf (buff, sizeof(buff), "MODE %s +", ch->name); /* CCC\0 */
    buff[t + MAXMODES] = '\0';
    FILL_BUFFER(bans,'b')
    FILL_BUFFER(exempts,'e')
    FILL_BUFFER(invites,'I')
    if (l)
      New_Request (to, 0, "%.*s%s", t + l, buff, &buff[t + MAXMODES + 1]);
  }
}

void ircd_channels_report (INTERFACE *to)
{
  //TODO.......
}

static inline void _ircd_do_reop(IRCD *ircd, CLIENT *me, CHANNEL *ch)
{
  MEMBER *who = ch->users;
  const char *cmask;

  ch->noop_since = 0;			/* operator is adding so reset this */
  //TODO: find local client with the least idle
  //TODO: if not found then op some random user
  who->mode |= A_OP;
  ircd_sendto_chan_local(ch, ":%s MODE %s +o %s", me->lcnick, ch->name,
			 who->who->nick);
#ifdef USE_SERVICES
  //TODO: notify local services too
#endif
  /* every server should know channel state too */
  cmask = strchr (ch->name, ':');
  if (cmask) {
    cmask++;
    ircd_sendto_servers_mask_new(ircd, NULL, cmask, ":%s IMODE %d %s +o %s",
				 me->lcnick, ircd_new_id(), ch->name,
				 who->who->nick);
    ircd_sendto_servers_mask_old(ircd, NULL, cmask, ":%s MODE %s +o %s",
				 me->lcnick, ch->name, who->who->nick);
    return;
  }
  ircd_sendto_servers_new(ircd, NULL, ":%s IMODE %d %s +o %s", me->lcnick,
			  ircd_new_id(), ch->name, who->who->nick);
  ircd_sendto_servers_old(ircd, NULL, ":%s MODE %s +o %s", me->lcnick, ch->name,
			  who->who->nick);
}

void ircd_channels_chreop(IRCD *ircd, CLIENT *me)
{
  LEAF *l = NULL;

  while ((l = Next_Leaf(ircd->channels, l, NULL)) != NULL) {
    register CHANNEL *ch = l->s.data;

    if ((ch->mode & A_REOP) && ch->users != NULL && ch->noop_since != 0 &&
	Time > ch->noop_since + REOP_DELAY)
	//TODO: add random time (0...REOP_DELAY) to that delay!
      _ircd_do_reop(ircd, me, ch);
  }
}

/* args: buf, umode, sizeof(buf); returns buf */
char *ircd_make_umode (char *buf, modeflag umode, size_t bufsize)
{
  _ircd_make_Xmode (_ircd_umodes, buf, umode, bufsize);
  return buf;
}

modeflag ircd_char2umode(INTERFACE *srv, const char *sname, char c)
{
  struct binding_t *b;
  modeflag mf = 0;
  char charstr[2];
#define static register
  BINDING_TYPE_ircd_umodechange ((*f));
#undef static

  charstr[0] = c;
  charstr[1] = '\0';
  b = Check_Bindtable (BTIrcdUmodechange, charstr, U_ALL, U_ANYCH, NULL);
  while (b) {			/* cycle thru all */
    if (!b->name)
      mf |= (f = (void *)b->func) (srv, sname, A_SERVER, 1);
    b = Check_Bindtable (BTIrcdUmodechange, charstr, U_ALL, U_ANYCH, b);
  }
  return mf;
}

modeflag ircd_char2mode(INTERFACE *srv, const char *sname, const char *tar,
			const char *chname, char c)
{
  const char *p;
  struct binding_t *b;
#define static register
  BINDING_TYPE_ircd_channel ((*ff));
  BINDING_TYPE_ircd_modechange ((*f));
#undef static
  int (*ma)(INTERFACE *, const char *, const char *, int, const char *);
  modeflag mf;
  char chfc[2];

  chfc[1] = '\0';
  if (c == '\0') {
    chfc[0] = chname[0];
    b = Check_Bindtable(BTIrcdChannel, chfc, U_ALL, U_ANYCH, NULL);
    if (b == NULL || b->name != NULL)
      return 0;
    return ((ff = (void *)b->func)(NULL, 0, 0, 0, chname,
				   ((IRCD *)srv->data)->channels, &p));
  }
  chfc[0] = c;
  if (!(p = strchr (Ircd_modechar_list, c)) /* check for compliance */
      || Ircd_whochar_list[p-Ircd_modechar_list] == ' ')
    return (0);
  mf = 0;
  b = Check_Bindtable (BTIrcdModechange, chfc, U_ALL, U_ANYCH, NULL);
  while (b != NULL)		/* cycle thru all */
  {
    if (!b->name)
    {
      f = (void *)b->func;
      mf |= f(srv, sname, (A_OP|A_ADMIN), tar, (modeflag)0, 1, chname[0], &ma);
    }
    b = Check_Bindtable (BTIrcdModechange, chfc, U_ALL, U_ANYCH, b);
  }
  return mf;
}

modeflag ircd_whochar2mode(char ch)
{
  register char *ptr;
  register size_t i;

  ptr = strchr(Ircd_whochar_list, ch);
  if (ptr == NULL)
    return (0);
  ch = Ircd_modechar_list[ptr-Ircd_whochar_list];
  for (i = 0; i < sizeof(_ircd_cmodes); i++)
    if (_ircd_cmodes[i] == ch)
      return (1 << i);
  return (0);
}


/* common end and start of channel protocol */
void ircd_channel_proto_end (void)
{
  Delete_Binding ("ircd-whochar", (Function)&iwc_ircd, NULL);
  Delete_Binding ("ircd-channel", (Function)&ich_normal, NULL);
  Delete_Binding ("ircd-channel", (Function)&ich_add, NULL);
  Delete_Binding ("ircd-channel", (Function)&ich_excl, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_mode_cb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_mode_sb, NULL);
#if IRCD_MULTICONNECT
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_imode, NULL);
#endif
  Delete_Binding ("ircd-client-cmd", &ircd_join_cb, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_o, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_v, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_a, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_i, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_m, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_n, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_q, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_p, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_s, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_r, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_t, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_k, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_l, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_b, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_e, NULL);
  Delete_Binding ("ircd-modechange", (Function)&imch_I, NULL);
  Delete_Binding ("ircd-umodechange", (Function)&iumch_a, NULL);
  Delete_Binding ("ircd-umodechange", (Function)&iumch_i, NULL);
  Delete_Binding ("ircd-umodechange", (Function)&iumch_w, NULL);
  Delete_Binding ("ircd-umodechange", (Function)&iumch_r, NULL);
  Delete_Binding ("ircd-umodechange", (Function)&iumch_o, NULL);
  Delete_Binding ("ircd-umodechange", (Function)&iumch_O, NULL);
  Delete_Binding ("ircd-umodechange", (Function)&iumch_s, NULL);
  Delete_Binding ("ircd-check-modechange", &ichmch_r, NULL);
  _forget_(CHANNEL);
  _forget_(MEMBER);
  _forget_(MASK);
  _ircd_internal_logger_sig (_ircd_internal_logger, S_TERMINATE); /* stop &* */
}

void ircd_channel_proto_start (IRCD *ircd)
{
  BTIrcdWhochar = Add_Bindtable ("ircd-whochar", B_MASK);
  BTIrcdChannel = Add_Bindtable ("ircd-channel", B_UNIQ);
  BTIrcdModechange = Add_Bindtable ("ircd-modechange", B_MATCHCASE);
  BTIrcdUmodechange = Add_Bindtable ("ircd-umodechange", B_MATCHCASE);
  BTIrcdCheckModechange = Add_Bindtable ("ircd-check-modechange", B_MASK);
  Add_Binding ("ircd-whochar", "*", 0, 0, (Function)&iwc_ircd, NULL);
  /* default 4 channel types, see RFC2811 */
  Add_Binding ("ircd-channel", "&", 0, 0, (Function)&ich_normal, NULL);
  Add_Binding ("ircd-channel", "#", 0, 0, (Function)&ich_normal, NULL);
  Add_Binding ("ircd-channel", "+", 0, 0, (Function)&ich_add, NULL);
  Add_Binding ("ircd-channel", "!", 0, 0, (Function)&ich_excl, NULL);
  /* those two do manipulate bindtables which are defined here */
  Add_Binding ("ircd-client-cmd", "mode", 0, 0, &ircd_mode_cb, NULL);
  Add_Binding ("ircd-server-cmd", "mode", 0, 0, (Function)&ircd_mode_sb, NULL);
#if IRCD_MULTICONNECT
  Add_Binding ("ircd-server-cmd", "imode", 0, 0, (Function)&ircd_imode, NULL);
#endif
  /* this one needs to check channel parameters before adding user */
  Add_Binding ("ircd-client-cmd", "join", 0, 0, &ircd_join_cb, NULL);
  /* default channel modes, see RFC2812 */
  Add_Binding ("ircd-modechange", "o", 0, 0, (Function)&imch_o, NULL);
  Add_Binding ("ircd-modechange", "v", 0, 0, (Function)&imch_v, NULL);
  Add_Binding ("ircd-modechange", "a", 0, 0, (Function)&imch_a, NULL);
  Add_Binding ("ircd-modechange", "i", 0, 0, (Function)&imch_i, NULL);
  Add_Binding ("ircd-modechange", "m", 0, 0, (Function)&imch_m, NULL);
  Add_Binding ("ircd-modechange", "n", 0, 0, (Function)&imch_n, NULL);
  Add_Binding ("ircd-modechange", "q", 0, 0, (Function)&imch_q, NULL);
  Add_Binding ("ircd-modechange", "p", 0, 0, (Function)&imch_p, NULL);
  Add_Binding ("ircd-modechange", "s", 0, 0, (Function)&imch_s, NULL);
  Add_Binding ("ircd-modechange", "r", 0, 0, (Function)&imch_r, NULL);
  Add_Binding ("ircd-modechange", "t", 0, 0, (Function)&imch_t, NULL);
  Add_Binding ("ircd-modechange", "k*", 0, 0, (Function)&imch_k, NULL);
  Add_Binding ("ircd-modechange", "l*", 0, 0, (Function)&imch_l, NULL);
  Add_Binding ("ircd-modechange", "b*", 0, 0, (Function)&imch_b, NULL);
  Add_Binding ("ircd-modechange", "e*", 0, 0, (Function)&imch_e, NULL);
  Add_Binding ("ircd-modechange", "I*", 0, 0, (Function)&imch_I, NULL);
  /* default user modes, see RFC2812 */
  Add_Binding ("ircd-umodechange", "a", 0, 0, (Function)&iumch_a, NULL);
  Add_Binding ("ircd-umodechange", "i", 0, 0, (Function)&iumch_i, NULL);
  Add_Binding ("ircd-umodechange", "w", 0, 0, (Function)&iumch_w, NULL);
  Add_Binding ("ircd-umodechange", "r", 0, 0, (Function)&iumch_r, NULL);
  Add_Binding ("ircd-umodechange", "o", 0, 0, (Function)&iumch_o, NULL);
  Add_Binding ("ircd-umodechange", "O", 0, 0, (Function)&iumch_O, NULL);
  Add_Binding ("ircd-umodechange", "s", 0, 0, (Function)&iumch_s, NULL);
  Add_Binding ("ircd-check-modechange", "*", 0, 0, &ichmch_r, NULL);
  Send_Signal (I_MODULE, "ircd*", S_FLUSH); /* apply bindings to modes list */
  /* create common local channels */
  _ircd_log_channel (ircd, "&KILLS", F_MODES);
  _ircd_log_channel (ircd, "&NOTICES", F_WARN);
  _ircd_log_channel (ircd, "&ERRORS", F_ERROR);
  _ircd_log_channel (ircd, "&LOCAL", F_CONN);
  _ircd_log_channel (ircd, "&CHANNEL", F_JOIN);
//  _ircd_log_channel ("&HASH", ?????);
//  _ircd_log_channel ("&NUMERICS", ?????);
  _ircd_log_channel (ircd, "&SERVERS", F_SERV);
}
#endif