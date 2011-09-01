/*
 * Copyright (C) 2000-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * The FoxEye "tcl" module.
 */

#include "foxeye.h"
#include "modules.h"

#ifdef HAVE_TCL
#define USE_NON_CONST 1 /* prevent CONST for newest versions of TCL */
#include <tcl.h>

#include "init.h"
#include "direct.h"
#include "conversion.h"
#include "list.h"
#include "sheduler.h"

typedef struct {
  char *intcl;
  char *name;
  int used;
} tcl_bindtable;

static tcl_bindtable tcl_bindtables[] = {
  { "dcc",	"dcc", 0 },
  { "chat",	"chat",	0 },
  { "act",	"chat-act", 0 },
  { "filt",	"in-filter", 0 },
  { "chon",	"chat-on", 0 },
  { "chof",	"chat-off", 0 },
  { "chjn",	"chat-join", 0 },
  { "chpt",	"chat-part", 0 },
  { "nkch",	"new-lname", 0 },
  { "load",	"load", 0 },
  { "unld",	"unload", 0 },
  { "join",	"irc-join", 0 },
  { "part",	"irc-part", 0 },
  { "kick",	"irc-kick", 0 },
  { "topc",	"irc-topic", 0 },
  { "mode",	"irc-modechg", 0 },
  { "rejn",	"irc-netjoin", 0 },
  { "rcvd",	"dcc-got", 0 },
  { "raw",	"irc-raw", 0 },
  { "pubm",	"irc-pub-msg-mask", 0 },
  { "pub",	"irc-pub-msg-cmd", 0 },
  { "msgm",	"irc-priv-msg-mask", 0 },
  { "notc",	"irc-priv-notice-mask", 0 },
  { "msg",	"irc-priv-msg-cmd", 0 },
  { "ctcp",	"irc-priv-msg-ctcp", 0 },
  { "ctcr",	"irc-priv-notice-ctcp", 0 },
  { "flud",	"irc-flood", 0 },
  { "nick",	"irc-nickchg", 0 },
  { "sign",	"irc-signoff", 0 },
  { "splt",	"irc-netsplit", 0 },
  { "sent",	"dcc-sent", 0 },
  { NULL,	NULL, 0 },
  { "evnt",	NULL, 0 },
  { "link",	NULL, 0 },
  { "disc",	NULL, 0 },
  { "wall",	NULL, 0 },
  { "bcst",	NULL, 0 },
  { "time",	NULL, 0 },
  { "away",	NULL, 0 },
  { "lost",	NULL, 0 },
  { "tout",	NULL, 0 },
  { "fil",	NULL, 0 },
  { "bot",	NULL, 0 },
  { "note",	NULL, 0 },
  { "need",	NULL, 0 },
  { NULL,	NULL, 0 }	/* this one must be last */
};

static Tcl_Interp *Interp = NULL;

#ifdef HAVE_TCL_SETSYSTEMENCODING
struct conversion_t *_Tcl_Conversion = NULL;
#endif

static char tcl_default_network[NAMEMAX+1] = "irc";
static long int tcl_max_timer = 2 * 24 * 3600;

static inline void ResultInteger (Tcl_Interp *tcl, int res)
{
#ifndef HAVE_TCL8X
  char var[32];

  snprintf (var, sizeof(var), "%d", res);
  Tcl_SetResult (tcl, var, TCL_VOLATILE);
#else
  Tcl_SetObjResult (tcl, Tcl_NewIntObj (res));
#endif
}

static inline void ResultString (Tcl_Interp *tcl, const char *res, size_t sz)
{
  char var[TCL_RESULT_SIZE];
#ifndef HAVE_TCL8X

  if (sz > sizeof(var))
    sz = sizeof(var);
  strfcpy (var, res, sz);
  Tcl_SetResult (tcl, var, TCL_VOLATILE);
#else
  char *ptr;

  ptr = var;
#ifdef HAVE_TCL_SETSYSTEMENCODING
  sz = Undo_Conversion(_Tcl_Conversion, &ptr, sizeof(var)-1, res, sz);
  if (ptr == var)
    var[sz] = '\0';
#endif
  Tcl_SetObjResult (tcl, Tcl_NewStringObj (ptr, sz));
#endif
}

static inline int _tcl_errret (Tcl_Interp *tcl, const char *err)
{
#ifndef HAVE_TCL8X
  char var[TCL_RESULT_SIZE];

  strfcpy (var, err, sizeof(var));
  Tcl_SetResult (tcl, var, TCL_VOLATILE);
#else
  Tcl_SetObjResult (tcl, Tcl_NewStringObj ((char *)err, sizeof(err)));
#endif
  return TCL_ERROR;
}

#ifdef HAVE_TCL8X
static inline int ArgInteger (Tcl_Interp *tcl, Tcl_Obj *obj)
{
  int i;

  if (Tcl_GetIntFromObj (tcl, obj, &i) == TCL_ERROR)
    i = -1;
  return i;
}
#else
# define ArgInteger(i,a) atoi(a)
#endif

#ifdef HAVE_TCL8X
# define TCLARGS Tcl_Obj *CONST		/* last argument of command */
# define ArgString Tcl_GetStringFromObj
#else
# define TCLARGS char *
# define ArgString(a,b) a, *(b) = safe_strlen (a)
#endif

static int _tcl_interface (char *, int, const char **);

/* ---------------------------------------------------------------------------
 * Calls from TCL to anywhere.
 */

/* functions of core/modules */
static int _tcl_call_function (ClientData func, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  char string[LONG_STRING];
  char buf[LONG_STRING];
  char *c, *cs = string, *ptr;
  size_t s, ss = sizeof(string) - 1;
  int i = 1;				/* skip function name */
  int (*f)(const char *) = func;

  while (--argc && ss)			/* make a string from argv[] */
  {
    c = ArgString (argv[i++], &s);
    if (cs != string)
    {
      *cs++ = ' ';
      ss--;
    }
    if (strchr (c, ' ') && ss > 2)	/* do quote if arg has spaces */
    {
      *cs++ = '"';
      ss -= 2;
# ifdef HAVE_TCL_SETSYSTEMENCODING
      ptr = buf;
      s = Do_Conversion(_Tcl_Conversion, &ptr, ss, c, s);
# else
      ptr = c;
      if (s > ss)
	s = ss;
# endif
      memcpy (ptr, c, s);
      cs[s] = '"';
      cs++;
    }
    else
    {
# ifdef HAVE_TCL_SETSYSTEMENCODING
      ptr = buf;
      s = Do_Conversion(_Tcl_Conversion, &ptr, ss, c, s);
# else
      ptr = c;
      if (s > ss)
	s = ss;
# endif
      memcpy (cs, c, s);
    }
    cs += s;
    ss -= s;
  }
  *cs = '\0';				/* terminate string in buffer */
  BindResult = NULL;			/* cleanup before call */
  i = f (string);			/* call function */
  if (i == 0)
  {
    if (BindResult)
      _tcl_errret (tcl, BindResult);
    return TCL_ERROR;
  }
  if (BindResult)
    ResultString (tcl, BindResult, strlen(BindResult)); /* return result */
  else
    ResultInteger (tcl, i);		/* result is numeric */
  return TCL_OK;
}

/* own functions */
static int _tcl_togflagtable[] = {
0,	0,	0,	0,	0,	0,	0,	0,	/*   - ' */
0,	0,	0,	0,	0,	U_NEGATE,0,	0,	/* ( - / */
0,	0,	0,	0,	0,	0,	0,	0,	/* 0 - 7 */
0,	0,	0,	0,	0,	0,	0,	0,	/* 8 - ? */
0,	U_FLA,	U_FLB,	U_FLC,	U_FLD,	U_FLE,	U_FLF,	U_FLG,	/* @ - G */
U_FLH,	0,	0,	0,	0,	0,	0,	0,	/* H - O */
0,	0,	0,	0,	0,	0,	0,	0,	/* P - W */
0,	0,	0,	0,	0,	0,	0,	0,	/* X - _ */
0,	0,	U_SPECIAL,0,	0,	0,	U_FRIEND,0,	/* ` - g */
0,	0,	U_HALFOP,0,	0,	U_MASTER,U_OWNER,0,	/* h - o */
U_ACCESS,U_QUIET,0,	0,	U_OP,	U_UNSHARED,U_VOICE,0,	/* p - w */
0,	0,	0	/* x - z */
};

#define _tcl_togflag(a,s,f) \
    for (;s;s--)\
      if (*a == '|' || *a == '&')\
	break;\
      else if (*a >= '-' && *a <= 'z')\
	f |= _tcl_togflagtable[*a++ - ' '];\
      else\
	a++

static int _tcl_tocflagtable[] = {
0,	0,	0,	0,	0,	0,	U_AND,	0,	/*   - ' */
0,	0,	0,	0,	0,	U_NEGATE,0,	0,	/* ( - / */
0,	0,	0,	0,	0,	0,	0,	0,	/* 0 - 7 */
0,	0,	0,	0,	0,	0,	0,	0,	/* 8 - ? */
0,	U_FLA,	U_FLB,	U_FLC,	U_FLD,	U_FLE,	U_FLF,	U_FLG,	/* @ - G */
U_FLH,	0,	0,	0,	0,	0,	0,	0,	/* H - O */
0,	0,	0,	0,	0,	0,	0,	0,	/* P - W */
0,	0,	0,	0,	0,	0,	0,	0,	/* X - _ */
0,	U_OP|U_AUTO,0,	0,	U_DEOP,	0,	U_FRIEND,U_SPEAK,/* ` - g */
0,	0,	0,	U_DENY,	U_HALFOP,U_MASTER,U_OWNER,U_OP,	/* h - o */
0,	U_QUIET,U_DEOP,	0,	0,	U_UNSHARED,U_VOICE,0,	/* p - w */
0,	U_HALFOP|U_AUTO,0	/* x - z */
};

#define _tcl_tocflag(a,s,f) \
    while (s--)\
      if (*a >= '&' && *a <= 'z')\
	f |= _tcl_tocflagtable[*a++ - ' '];\
      else\
	a++

			/* bind <type> <attr> key [cmd] */
static int _tcl_bind (ClientData cd, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  tcl_bindtable *tbt;
  char *c, *fn;
  size_t s;
  userflag gf, cf;
  char buf[32];

  if (argc < 4 || argc > 5)		/* check for number of params */
    return _tcl_errret (tcl, "bad number of parameters.");
  c = ArgString (argv[1], &s);		/* find <type> in list */
  if (c && s < 5 && s > 2)		/* eggdrop limits it to 3 or 4 */
  {
    unistrlower (buf, c, 5);
    for (tbt = &tcl_bindtables[0]; tbt->intcl; tbt++)
      if (strlen (tbt->intcl) == s && !memcmp (buf, tbt->intcl, 4))
	break;
  }
  else
    return _tcl_errret (tcl, "bad bindtable name.");
  if (!tbt->name)
    return _tcl_errret (tcl, "bindtable isn't found.");
  c = ArgString (argv[2], &s);		/* calculate attr(s) */
  gf = 0;
  _tcl_togflag (c, s, gf);
  if (gf == U_NEGATE)			/* nothing to negate */
    gf = 0;
  cf = 0;
  _tcl_tocflag (c, s, cf);
  if (!(cf & ~(U_NEGATE | U_AND)))	/* nothing to negate or and */
    cf = 0;
  /* FIXME: do conversion on key/mask */
  c = ArgString (argv[3], &s);		/* it's key/mask now */
  if (argc == 3) /* if no command name then find and return binding name */
  {
    struct bindtable_t *bt = Add_Bindtable (tbt->name, B_UNDEF);
    struct binding_t *bind = Check_Bindtable (bt, c, gf, cf | U_EQUAL, NULL);

    if (bind && bind->name && bind->func == &_tcl_interface)
      ResultString (tcl, bind->name, strlen (bind->name));
    return TCL_OK;			/* how to notify we have result? */
  }
  fn = ArgString (argv[4], &s);
  Add_Binding (tbt->name, c, gf, cf, &_tcl_interface, fn); /* add binding */
  tbt->used = 1;
  return TCL_OK;
}

			/* unbind type <*> <*> cmd */
static int _tcl_unbind (ClientData cd, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  tcl_bindtable *tbt;
  char *c;
  size_t s;
  char buf[5];

  if (argc != 5)			/* check for number of params */
    return _tcl_errret (tcl, "bad number of parameters.");
  c = ArgString (argv[1], &s);		/* find <type> in list */
  if (c && s < 5 && s > 2)		/* eggdrop limits it to 3 or 4 */
  {
    unistrlower (buf, c, 5);
    for (tbt = &tcl_bindtables[0]; tbt->intcl; tbt++)
      if (strlen (tbt->intcl) == s && !memcmp (buf, tbt->intcl, 4))
	break;
  }
  else
    return _tcl_errret (tcl, "bad bindtable name.");
  if (!tbt->name)
    return _tcl_errret (tcl, "bindtable isn't found.");
  /* we ignore attr(s) and mask due to difference with eggdrop, sorry */
  c = ArgString (argv[4], &s);		/* it's command name now */
  Delete_Binding (tbt->name, &_tcl_interface, c);
  return TCL_OK;
}

			/* send_request <to> <type> <mode> text */
static int _tcl_send_request (ClientData cd, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  size_t s;
  char *to, *c, *t;
  iftype_t ift;
  flag_t fl;
#ifdef HAVE_TCL_SETSYSTEMENCODING
  char *ptr;
  char target[NAMEMAX+1];
  char message[MESSAGEMAX+1];
#endif
  static char *typec = "dncl";
  static iftype_t typev[] = {I_DCCALIAS,I_SERVICE,I_CLIENT,I_LOG};
  static char *flagc = "0124pmtcbsodjkw-";
  static flag_t flagv[] = {F_T_MESSAGE,F_T_NOTICE,F_T_CTCP,F_T_ACTION,F_PUBLIC,
			  F_PRIV,F_BOTNET,F_CMDS,F_CONN,F_SERV,
			  F_WARN,F_DEBUG,F_JOIN,F_MODES,F_WALL,F_QUICK};

  if (argc != 5)
    return _tcl_errret (tcl, "bad number of parameters.");
  c = ArgString (argv[2], &s);
  for (ift = 0; s; s--)			/* get type from chars */
    if ((t = strchr (typec, *c++)))
      ift |= typev[t - typec];
  c = ArgString (argv[3], &s);
  for (fl = 0; s; s--)			/* get flag from chars */
    if ((t = strchr (flagc, *c++)))
      fl |= flagv[t - flagc];
  t = ArgString (argv[4], &s);		/* text of message */
#ifdef HAVE_TCL_SETSYSTEMENCODING
  ptr = message;
  s = Do_Conversion(_Tcl_Conversion, &ptr, sizeof(message)-1, t, s);
  if (ptr == message)
    message[s] = '\0';
  t = ptr;
#endif
  to = ArgString (argv[1], &s);		/* target of message */
  DBG("_tcl_send_request:to=%s mode=%s msg=%s", to, c, t);
#ifdef HAVE_TCL_SETSYSTEMENCODING
  ptr = target;
  s = Do_Conversion(_Tcl_Conversion, &ptr, sizeof(target)-1, to, s);
  if (ptr == target)
    target[s] = '\0';
  to = ptr;
#endif
  Add_Request (ift, to, fl, "%s", t);	/* send message! */
  return TCL_OK;
}

			/* ison <service> [lname] */
static int _tcl_ison (ClientData cd, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  const char *service, *lname;
  size_t s;

  if (argc < 2 || argc > 3)		/* check for number of params */
    return _tcl_errret (tcl, "bad number of parameters.");
  service = ArgString (argv[1], &s);	/* service name */
  /* FIXME: do conversion on service and Lname */
  if (argc == 2)			/* no lname provided */
    lname = NULL;
  else
    lname = ArgString (argv[2], &s);
  if (!Lname_IsOn (service, NULL, lname, &lname))
    lname = NULL;
  ResultString (tcl, NONULL(lname), safe_strlen(lname));
  return TCL_OK;			/* we got some result, nice */
}

			/* check_flags <lname> <flags> [service] */
static int _tcl_check_flags (ClientData cd, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  char *lname, *c;
  size_t s;
  userflag cf, rf;

  if (argc < 3 || argc > 4)		/* check for number of params */
    return _tcl_errret (tcl, "bad number of parameters.");
  lname = ArgString (argv[1], &s);
  /* FIXME: do conversion on service and Lname */
  c = ArgString (argv[2], &s);		/* calculate attr(s) */
  cf = 0;
  if (argc == 3)			/* global, i.e. network flags asked */
  {
    _tcl_togflag (c, s, cf);
    rf = Get_Clientflags (lname, tcl_default_network) |
	  Get_Clientflags (lname, NULL);
  }
  else
  {
    _tcl_tocflag (c, s, cf);
    c = ArgString (argv[3], &s);	/* service name */
    rf = Get_Clientflags (lname, c);
  }
  if ((rf & cf) == cf)			/* flags matched! */
    ResultInteger (tcl, 1);
  else
    ResultInteger (tcl, 0);
  return TCL_OK;
}

typedef struct tcl_timer
{
  tid_t tid;
  time_t when;
  char *cmd;
  struct tcl_timer *prev;
} tcl_timer;

ALLOCATABLE_TYPE (tcl_timer, TT_, prev)

static tcl_timer *Tcl_Last_Timer = NULL;

			/* utimer <time> <cmd> */
static int _tcl_utimer (ClientData cd, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  char *c;
  int n;
  size_t s;
  tcl_timer *tt;

  if (argc != 3)			/* check for number of params */
    return _tcl_errret (tcl, "bad number of parameters.");
  n = ArgInteger (tcl, argv[1]);	/* timer */
  c = ArgString (argv[2], &s);		/* cmd */
  if (!*c || n < 0 || n > tcl_max_timer)
    return _tcl_errret (tcl, "invalid parameters for utimer");
  tt = alloc_tcl_timer();
  tt->tid = NewTimer (I_MODULE, "tcl", S_LOCAL, (unsigned int)n, 0, 0, 0);
  tt->cmd = safe_strdup (c);
  tt->when = Time + n;
  tt->prev = Tcl_Last_Timer;
  Tcl_Last_Timer = tt;
  dprint (3, "tcl:_tcl_utimer:added timer for %lu", (unsigned long int)tt->when);
  ResultInteger (tcl, (int)tt->tid);
  return TCL_OK;
}

			/* killutimer <timerid> */
static int _tcl_killutimer (ClientData cd, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  int n;
  tcl_timer *tt, **ptt;

  if (argc != 2)			/* check for number of params */
    return _tcl_errret (tcl, "bad number of parameters.");
  n = ArgInteger (tcl, argv[1]);		/* tid */
  for (ptt = &Tcl_Last_Timer; (tt = *ptt); ptt = &tt->prev)
    if ((int)tt->tid == n)
      break;
  if (!tt)
    return _tcl_errret (tcl, "this timer-id is not active.");
  *ptt = tt->prev;
  KillTimer (tt->tid);
  FREE (&tt->cmd);
  dprint (3, "tcl:_tcl_killutimer:removed timer for %lu", (unsigned long int)tt->when);
  free_tcl_timer (tt);
  return TCL_OK;
}

static void _tcl_add_own_procs (void)
{
#ifdef HAVE_TCL8X
# define NB(a) Tcl_CreateObjCommand(Interp,#a,&_tcl_##a,NULL,NULL)
#else
# define NB(a) Tcl_CreateCommand(Interp,#a,&_tcl_##a,NULL,NULL)
#endif
  NB (bind);
  NB (unbind);
  NB (send_request);
  NB (ison);
  NB (check_flags);
  NB (utimer);
  NB (killutimer);
#undef NB
}


/* ---------------------------------------------------------------------------
 * Requests from TCL to variables.
 */

typedef struct
{
  void *data;
  size_t len;
# ifdef HAVE_TCL8X
  Tcl_Obj *name;
# endif
} tcl_data;

#define vardata ((tcl_data *)data)
static char *_trace_int (ClientData data, Tcl_Interp *tcl,
			 char *name1, char *name2, int flags)
{
#ifndef HAVE_TCL8X
  int i;
#else
  long l;
#endif

  if (flags & TCL_TRACE_UNSETS)	/* deleting it */
  {
    dprint (4, "tcl:_trace_int: deleted %s.%s", name1, NONULL(name2));
#ifdef HAVE_TCL8X
    Tcl_DecrRefCount (vardata->name);
#endif
    FREE (&data);
  }
  else if (flags & TCL_TRACE_WRITES)
  {
#ifdef HAVE_TCL8X
    if (Tcl_GetLongFromObj (tcl,
		Tcl_ObjGetVar2 (tcl, vardata->name, NULL, TCL_GLOBAL_ONLY),
		&l) == TCL_ERROR)
      return Tcl_GetStringResult (tcl);
    *(long int *)vardata->data = l;
    dprint (4, "tcl:_trace_int: changed %s.%s to %ld", name1, NONULL(name2), l);
#else
    if (Tcl_GetInt (tcl, Tcl_GetVar2 (tcl, name1, name2, TCL_GLOBAL_ONLY),
		    &i) == TCL_ERROR)
      return tcl->result;
    *(long int *)vardata->data = (long int)i;
    dprint (4, "tcl:_trace_int: changed %s.%s to %d", name1, NONULL(name2), i);
#endif
  }
  else if (flags & TCL_TRACE_READS)
  {
    dprint (4, "tcl:_trace_int: read %s.%s", name1, NONULL(name2));
#ifdef HAVE_TCL8X
    Tcl_ObjSetVar2 (tcl, vardata->name, NULL,
		    Tcl_NewLongObj (*(long int *)vardata->data),
		    TCL_GLOBAL_ONLY);
#else
    char value[32];

    snprintf (value, sizeof(value), "%ld", *(long int *)vardata->data);
    Tcl_SetVar2 (tcl, name1, name2, value, TCL_GLOBAL_ONLY);
#endif
  }
  else
    ERROR ("tcl:_trace_int: unknown flags %d", flags);
  return NULL;
}

static char *_trace_bool (ClientData data, Tcl_Interp *tcl,
			  char *name1, char *name2, int flags)
{
  int i;

  if (flags & TCL_TRACE_UNSETS)	/* deleting it */
  {
    dprint (4, "tcl:_trace_bool: deleted %s.%s", name1, NONULL(name2));
#ifdef HAVE_TCL8X
    Tcl_DecrRefCount (vardata->name);
#endif
    FREE (&data);
  }
  else if (flags & TCL_TRACE_WRITES)
  {
#ifdef HAVE_TCL8X
    if (Tcl_GetBooleanFromObj (tcl,
		Tcl_ObjGetVar2 (tcl, vardata->name, NULL, TCL_GLOBAL_ONLY),
		&i) == TCL_ERROR)
      return Tcl_GetStringResult (tcl);
#else
    if (Tcl_GetBoolean (tcl, Tcl_GetVar2 (tcl, name1, name2, TCL_GLOBAL_ONLY),
		&i) == TCL_ERROR)
      return tcl->result;
#endif
    /* changing only flag TRUE, don't touch ASK and CAN_ASK */
    *(bool *)vardata->data &= ~TRUE;		/* reset it */
    *(bool *)vardata->data |= (bool)(i & TRUE);	/* update it */
    dprint (4, "tcl:_trace_bool: changed %s.%s to %s", name1, NONULL(name2),
	    (i & TRUE) ? "TRUE" : "FALSE");
  }
  else if (flags & TCL_TRACE_READS)
  {
    dprint (4, "tcl:_trace_bool:read %s.%s", name1, NONULL(name2));
#ifdef HAVE_TCL8X
    Tcl_ObjSetVar2 (tcl, vardata->name, NULL,
		    Tcl_NewBooleanObj ((int)(*(bool *)vardata->data & TRUE)),
		    TCL_GLOBAL_ONLY);
#else
    char value[4];

    snprintf (value, sizeof(value), "%d",
	      ((int)(*(bool *)vardata->data & TRUE)));
    Tcl_SetVar2 (tcl, name1, name2, value, TCL_GLOBAL_ONLY);
#endif
  }
  else
    ERROR ("tcl:_trace_bool: unknown flags %d", flags);
  return NULL;
}

static char *_trace_str (ClientData data, Tcl_Interp *tcl,
			 char *name1, char *name2, int flags)
{
  int i;
  char *s;
#ifdef HAVE_TCL_SETSYSTEMENCODING
  char buf[LONG_STRING];
  char *ptr;
#endif

  if (flags & TCL_TRACE_UNSETS)	/* deleting it */
  {
    dprint (4, "tcl:_trace_str: deleted %s.%s", name1, NONULL(name2));
#ifdef HAVE_TCL8X
    Tcl_DecrRefCount (vardata->name);
#endif
    FREE (&data);
  }
  else if (flags & TCL_TRACE_WRITES)
  {
#ifdef HAVE_TCL8X
    if (!(s = Tcl_GetStringFromObj (Tcl_ObjGetVar2 (tcl,
	vardata->name, NULL, TCL_GLOBAL_ONLY), &i)))
      return Tcl_GetStringResult (tcl);
# ifdef HAVE_TCL_SETSYSTEMENCODING
    ptr = buf;
    i = Do_Conversion(_Tcl_Conversion, &ptr, sizeof(buf), s, i);
    if (ptr == buf)
      buf[i] = '\0';
    s = ptr;
# endif
#else
    if (!(s = Tcl_GetVar2 (tcl, name1, name2, TCL_GLOBAL_ONLY)))
      return tcl->result;
    i = safe_strlen (s);
#endif
    if (i >= 0 && (size_t)i < vardata->len)
      strfcpy ((char *)vardata->data, s, i + 1);
    else
      strfcpy ((char *)vardata->data, s, vardata->len);
    dprint (4, "tcl:_trace_str: changed %s.%s to %s", name1, NONULL(name2), s);
  }
  else if (flags & TCL_TRACE_READS)
  {
    dprint (4, "tcl:_trace_str: read %s.%s", name1, NONULL(name2));
#ifdef HAVE_TCL8X
# ifdef HAVE_TCL_SETSYSTEMENCODING
    ptr = buf;
    i = Undo_Conversion(_Tcl_Conversion, &ptr, sizeof(buf), vardata->data,
			safe_strlen (vardata->data));
    if (ptr == buf)
      buf[i] = '\0';
# else
    ptr = vardata->data;
    i = safe_strlen (vardata->data);
# endif
    Tcl_ObjSetVar2 (tcl, vardata->name, NULL,
		    Tcl_NewStringObj (ptr, i), TCL_GLOBAL_ONLY);
#else
    Tcl_SetVar2 (tcl, name1, name2, vardata->data, TCL_GLOBAL_ONLY);
#endif
  }
  else
    ERROR ("tcl:_trace_str: unknown flags %d", flags);
  return NULL;
}

static char *_trace_stat (ClientData data, Tcl_Interp *tcl,
			  char *name1, char *name2, int flags)
{
  if (flags & TCL_TRACE_UNSETS)	/* deleting it */
  {
    dprint (4, "tcl:_trace_stat: deleted %s.%s", name1, NONULL(name2));
#ifdef HAVE_TCL8X
    Tcl_DecrRefCount (vardata->name);
#endif
    FREE (&data);
  }
  else if (flags & TCL_TRACE_WRITES)	/* reset it in TCL */
  {
    dprint (4, "tcl:_trace_stat: tried to change %s.%s", name1, NONULL(name2));
#ifdef HAVE_TCL8X
    /* TODO: use Undo_Conversion here? */
    Tcl_ObjSetVar2 (tcl, vardata->name, NULL,
		Tcl_NewStringObj (vardata->data, safe_strlen (vardata->data)),
		TCL_GLOBAL_ONLY);
#else
    Tcl_SetVar2 (tcl, name1, name2, vardata->data, TCL_GLOBAL_ONLY);
#endif
    return "this variable is read only";
  }
  return NULL;
}
#undef vardata

/* ---------------------------------------------------------------------------
 * Calls from anywhere to TCL.
 */

#define _tcl_dashtound(a,b) do {\
  register char *t=a;\
  while (*b && t < &a[sizeof(a)-1]) {\
    if (*b == '-') *t++ = '_';\
    else *t++ = *b;\
    b++; }\
  *t = '\0';\
} while(0)

BINDING_TYPE_register(tcl_register_var);
static int tcl_register_var (const char *name, void *ptr, size_t s)
{
  tcl_data *data;
  char tn[STRING];
#ifndef HAVE_TCL8X
  char value[32];
#endif

  /* set new instance */
  data = safe_calloc (1, sizeof(tcl_data));
  data->data = ptr;
  data->len = s;
  _tcl_dashtound (tn, name);
  /* unset previous value if it exists! */
  Tcl_UnsetVar (Interp, tn, TCL_GLOBAL_ONLY);	/* ignore any error */
#ifdef HAVE_TCL8X
  data->name = Tcl_NewStringObj (tn, safe_strlen (tn));
  Tcl_IncrRefCount (data->name);
#endif
  switch (s)
  {
    case 0:	/* integer */
#ifdef HAVE_TCL8X
      Tcl_ObjSetVar2 (Interp, data->name, NULL,
		      Tcl_NewLongObj (*(long int *)ptr),
		      TCL_GLOBAL_ONLY);
#else
      snprintf (value, sizeof(value), "%ld", *(long int *)ptr);
      Tcl_SetVar (Interp, tn, value, TCL_GLOBAL_ONLY);
#endif
      Tcl_TraceVar (Interp, tn,
		    TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
		    &_trace_int, (ClientData)data);
      break;
    case 1:	/* boolean */
#ifdef HAVE_TCL8X
      Tcl_ObjSetVar2 (Interp, data->name, NULL,
		      Tcl_NewBooleanObj ((int)(*(bool *)ptr & TRUE)),
		      TCL_GLOBAL_ONLY);
#else
      snprintf (value, sizeof(value), "%d", (int)(*(bool *)ptr & TRUE));
      Tcl_SetVar (Interp, tn, value, TCL_GLOBAL_ONLY);
#endif
      Tcl_TraceVar (Interp, tn,
		    TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
		    &_trace_bool, (ClientData)data);
      break;
    case 2:	/* read-only */
#ifdef HAVE_TCL8X
      Tcl_ObjSetVar2 (Interp, data->name, NULL,
		      Tcl_NewStringObj (ptr, safe_strlen (ptr)),
		      TCL_GLOBAL_ONLY);
#else
      Tcl_SetVar (Interp, tn, ptr, TCL_GLOBAL_ONLY);
#endif
      Tcl_TraceVar (Interp, tn, TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
		    &_trace_stat, (ClientData)data);
      break;
    default:	/* string */
#ifdef HAVE_TCL8X
      /* TODO: use Undo_Conversion here? */
      Tcl_ObjSetVar2 (Interp, data->name, NULL,
		      Tcl_NewStringObj (ptr, safe_strlen (ptr)),
		      TCL_GLOBAL_ONLY);
#else
      Tcl_SetVar (Interp, tn, ptr, TCL_GLOBAL_ONLY);
#endif
      Tcl_TraceVar (Interp, tn,
		    TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
		    &_trace_str, (ClientData)data);
  }
  dprint (4, "tcl:registered variable %s/%d. (hope prev instance is deleted)",
	  tn, (int)s);
  return 1;
}

BINDING_TYPE_unregister(tcl_unregister_var);
static int tcl_unregister_var (const char *name)
{
  char tn[STRING];

  _tcl_dashtound (tn, name);
  if (Tcl_UnsetVar (Interp, tn, TCL_GLOBAL_ONLY) == TCL_OK)
    return 1;
  ERROR ("tcl:unregister variable %s failed: %s", tn,
#ifdef HAVE_TCL8X
	 Tcl_GetStringResult (Interp));
#else
	 Interp->result);
#endif
  return 0;
}

BINDING_TYPE_function(tcl_register_func);
static int tcl_register_func (const char *name, int (*func) (const char *))
{
#ifdef HAVE_TCL8X
  if (Tcl_CreateObjCommand
#else
  if (Tcl_CreateCommand
#endif
	/* casting (char *) below due to wrong prototypes in old tcl */
	(Interp, (char *)name, &_tcl_call_function, (ClientData)func, NULL) == TCL_OK)
    return 1;
  return 0;		/* error */
}

BINDING_TYPE_unfunction(tcl_unregister_func);
static int tcl_unregister_func (const char *name)
{
  /* casting (char *) below due to wrong prototypes in old tcl */
  if (Tcl_DeleteCommand (Interp, (char *)name) == TCL_OK)
    return 1;
  ERROR ("tcl:unregister function %s failed: %s", name,
#ifdef HAVE_TCL8X
	 Tcl_GetStringResult (Interp));
#else
	 Interp->result);
#endif
  return 0;		/* error */
}

BINDING_TYPE_script(script_tcl);
static int script_tcl (char *filename)
{
  DBG ("tcl:script_tcl:trying %s", filename);
  if (Tcl_EvalFile (Interp, filename) == TCL_OK)
    return 1;				/* success! */
  if (!strchr (filename, '/'))		/* relative path? try SCRIPTSDIR */
  {
    char fn[LONG_STRING];

    Add_Request (I_LOG, "*", F_WARN,
		 "TCL: file %s not found, trying default path.", filename);
    strfcpy (fn, SCRIPTSDIR "/", sizeof(fn));
    strfcat (fn, filename, sizeof(fn));
    DBG ("tcl:script_tcl:trying %s", fn);
    if (Tcl_EvalFile (Interp, fn) == TCL_OK)
      return 1;				/* success! */
  }
  ERROR ("tcl:execution of \"%s\" failed: %s", filename,
#ifdef HAVE_TCL8X
	 Tcl_GetStringResult (Interp));
#else
	 Interp->result);
#endif
  return 0;
}

BINDING_TYPE_dcc(dc_tcl);
static int dc_tcl (struct peer_t *from, char *args)
{
  char *c;

  if (!(c = args))
    return 0;
#ifdef HAVE_TCL8X
  Tcl_ResetResult (Interp);		/* reset it before run */
#else
  Interp->result = NULL;
#endif
  if (Tcl_Eval (Interp, c) == TCL_OK)	/* success! */
  {
#ifdef HAVE_TCL8X
# ifdef HAVE_TCL_SETSYSTEMENCODING
    char *ptr;
    register size_t s;
    char buf[MESSAGEMAX+1];

# endif
    c = Tcl_GetStringResult (Interp);
# ifdef HAVE_TCL_SETSYSTEMENCODING
    if (c) {
      ptr = buf;
      s = Do_Conversion(_Tcl_Conversion, &ptr, sizeof(buf), c, strlen(c));
      if (ptr == buf)
	buf[s] = '\0';
      c = ptr;
    }
# endif
    if (c)
#else
    if ((c = Interp->result))
#endif
      New_Request (from->iface, 0, _("TCL: result was: %s"), c);
  }
  else
    New_Request (from->iface, 0, _("TCL: execution failed: %s"),
#ifdef HAVE_TCL8X
		Tcl_GetStringResult (Interp));
#else
		Interp->result);
#endif
  return 1;
}

/* interpreter interface for everyone */
static int _tcl_interface (char *fname, int argc, const char *argv[])
{
  int i;
#ifdef HAVE_TCLEVALOBJV
  Tcl_Obj *objv[10];			/* I hope it's enough */
#else
  char cmd[40];				/* the same */
  char vn[8];
#endif
#ifdef HAVE_TCL_SETSYSTEMENCODING
  char buf[LONG_STRING];
#endif
  char *ptr;
  size_t psize;

  if (!fname || !*fname)		/* nothing to do */
    return 0;
  if (!safe_strcmp ("-", fname))	/* they asked my name */
  {
    BindResult = "tcl";
    return 1;
  }
#ifdef HAVE_TCL8X
  Tcl_ResetResult (Interp);		/* reset it before run */
#else
  Interp->result = NULL;
#endif
  /* now it's time to call TCL */
  if (argc > 8)
    argc = 8;
#ifdef HAVE_TCLEVALOBJV
  objv[0] = Tcl_NewStringObj (fname, safe_strlen (fname)); /* assume it's ascii */
  for (i = 0; i < argc; i++) {
    psize = safe_strlen (argv[i]);
#ifdef HAVE_TCL_SETSYSTEMENCODING
    ptr = buf;
    psize = Undo_Conversion(_Tcl_Conversion, &ptr, sizeof(buf), argv[i], psize);
    if (ptr == buf)
      buf[psize] = '\0';
#else
    ptr = argv[i];
#endif
    objv[i + 1] = Tcl_NewStringObj (ptr, psize);
  }
  i = Tcl_EvalObjv (Interp, argc + 1, objv, TCL_GLOBAL_ONLY);
#else
  cmd[0] = 0;
  for (i = 0; i < argc; i++)
  {
    snprintf (vn, sizeof(vn), " $_a%d", i);
    /* casting (char *) below due to wrong prototypes in old tcl */
#ifdef HAVE_TCL_SETSYSTEMENCODING
    ptr = buf;
    psize = Undo_Conversion(_Tcl_Conversion, &ptr, sizeof(buf), argv[i],
			    safe_strlen(argv[i]));
    if (ptr == buf)
      buf[psize] = '\0';
#else
    ptr = argv[i];
#endif
    Tcl_SetVar (Interp, &vn[2], (char *)ptr, TCL_GLOBAL_ONLY);	/* _aX */
    strfcat (cmd, vn, sizeof(cmd));				/* " $_aX" */
  }
  i = Tcl_VarEval (Interp, fname, cmd, NULL);
#endif
  if (i == TCL_OK)			/* setting BindResult if all went OK */
  {
#ifdef HAVE_TCL8X
# ifdef HAVE_TCL_SETSYSTEMENCODING
    char buf[LONG_STRING];
    char *ptr = buf;
    size_t s;
# endif
    BindResult = Tcl_GetStringResult (Interp);
    DBG("_tcl_interface:fname=%s result=%s", fname, NONULLP(BindResult));
# ifdef HAVE_TCL_SETSYSTEMENCODING
    s = Do_Conversion(_Tcl_Conversion, &ptr, sizeof(buf), BindResult,
		      safe_strlen(BindResult));
    BindResult = Tcl_GetString(Tcl_NewStringObj(ptr, s));
# endif
#else
    BindResult = Interp->result;
    DBG("_tcl_interface:fname=%s result=%s", fname, NONULLP(BindResult));
#endif
    if (BindResult && ((i = atoi (BindResult)) == 1 || i == -1))
      return i;				/* 1 and -1 are valid values */
    return 0;
  }
  Add_Request (I_LOG, "*", F_WARN, _("TCL: executing %s returned error: %s"),
#ifdef HAVE_TCL8X
	       fname, Tcl_GetStringResult (Interp));
#else
	       fname, Interp->result);
#endif
  return 0;
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log,
 *  S_REG - register everything.
 */
static iftype_t module_signal (INTERFACE *iface, ifsig_t sig)
{
  tcl_bindtable *tbt;
  tcl_timer *tt, **ptt;
  int i;
  INTERFACE *tmp;

  switch (sig)
  {
    case S_TERMINATE:
      for (tbt = &tcl_bindtables[0]; tbt->intcl; tbt++)
	if (tbt->used)	/* delete my interpreter from bindtables */
	  Delete_Binding (tbt->name, &_tcl_interface, NULL);
      Delete_Binding ("script", &script_tcl, NULL);
      Delete_Binding ("register", &tcl_register_var, NULL);
      Delete_Binding ("function", &tcl_register_func, NULL);
      Delete_Binding ("unregister", &tcl_unregister_var, NULL);
      Delete_Binding ("unfunction", &tcl_unregister_func, NULL);
      Delete_Binding ("dcc", &dc_tcl, NULL);
      while ((tt = Tcl_Last_Timer))	/* remove all timers */
      {
	Tcl_Last_Timer = tt->prev;
	KillTimer (tt->tid);
	FREE (&tt->cmd);
	free_tcl_timer (tt);
      }
      Tcl_DeleteInterp (Interp);	/* stop interpreter */
      if (!Tcl_InterpDeleted(Interp))
	WARNING("Tcl_InterpDeleted returned 0 after Tcl_DeleteInterp!");
      Tcl_Release((ClientData)Interp);
      Interp = NULL;
#ifdef HAVE_TCL_SETSYSTEMENCODING
      Free_Conversion(_Tcl_Conversion);
      _Tcl_Conversion = NULL;
#endif
      UnregisterVariable ("tcl-default-network");
      UnregisterVariable ("tcl-max-timer");
      Delete_Help ("tcl");
      _forget_(tcl_timer);
      iface->ift |= I_DIED;		/* done */
      break;
    case S_REG:
      Add_Request (I_INIT, "*", F_REPORT, "module tcl");
      RegisterString ("tcl-default-network", tcl_default_network,
		      sizeof(tcl_default_network), 0);
      RegisterInteger ("tcl-max-timer", &tcl_max_timer);
      break;
    case S_LOCAL:
      for (ptt = &Tcl_Last_Timer; (tt = *ptt); ptt = &tt->prev)
	if (tt->when <= Time)		/* finds first matched */
	  break;
	else
	  DBG ("tcl:timer:skipping timer %lu.", (unsigned long int)tt->when);
      if (!tt)
      {
	ERROR ("tcl:timer:not found timer for %lu.", (unsigned long int)Time);
	break;
      }
      dprint (4, "tcl:timer:found sheduled (%lu->%lu) cmd: %s",
	      (unsigned long int)tt->when, (unsigned long int)Time, tt->cmd);
      if (Tcl_Eval (Interp, tt->cmd) != TCL_OK)
      {
#ifdef HAVE_TCL8X
	ERROR ("TCL timer: execution failed: %s", Tcl_GetStringResult (Interp));
#else
	ERROR ("TCL timer: execution failed: %s", Interp->result);
#endif
      }
      FREE (&tt->cmd);
      *ptt = tt->prev;
      free_tcl_timer (tt);
      break;
    case S_REPORT:
      for (i = 0, tbt = &tcl_bindtables[0]; tbt->intcl; tbt++)
	if (tbt->used)
	  i++;
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "Module tcl: %d bindtables in use, %u/%u timers active.",
		   i, TT_num, TT_max);
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
SigFunction ModuleInit (char *args)
{
  /* kill old interpreter */
  if (Interp)
    Tcl_DeleteInterp (Interp);
  /* init Tcl interpreter */
  Interp = Tcl_CreateInterp();
  Tcl_Preserve((ClientData)Interp);
  Tcl_FindExecutable(RunPath);
  Tcl_SourceRCFile(Interp);
#ifdef HAVE_TCL_SETSYSTEMENCODING
  if (*Charset && strcasecmp(Charset, "UTF-8")) {
    char enc[SHORT_STRING];

    unistrlower(enc, Charset, sizeof(enc));
    if (!memcmp(enc, "mac", 3))
      enc[3] |= 0x20;		/* macXxxx are non-all-lowercase names for Tcl */
    if (Tcl_SetSystemEncoding(Interp, enc) != TCL_OK)
      Add_Request(I_LOG, "*", F_BOOT, "Warning: charset %s unknown for Tcl: %s",
		  enc, Tcl_GetStringResult (Interp));
  }
  _Tcl_Conversion = Get_Conversion("UTF-8");
#endif
  /* add interface from TCL to core */
  _tcl_add_own_procs();
  /* add interface from core to TCL */
  Add_Binding ("script", "*.tcl", 0, 0, &script_tcl, NULL);
  Add_Binding ("register", NULL, 0, 0, &tcl_register_var, NULL);
  Add_Binding ("function", NULL, 0, 0, &tcl_register_func, NULL);
  Add_Binding ("unregister", NULL, 0, 0, &tcl_unregister_var, NULL);
  Add_Binding ("unfunction", NULL, 0, 0, &tcl_unregister_func, NULL);
  Add_Binding ("dcc", "tcl", U_OWNER, U_NONE, &dc_tcl, NULL);
  /* register core and modules data into TCL */
  Send_Signal (I_MODULE | I_INIT, "*", S_REG);
  RegisterString ("tcl-default-network", tcl_default_network,
		  sizeof(tcl_default_network), 0);
  RegisterInteger ("tcl-max-timer", &tcl_max_timer);
  Add_Help ("tcl");
  return (&module_signal);
}
#else /* not HAVE_TCL */
SigFunction ModuleInit (char *args)
{
  ERROR ("Cannot run TCL, there is not any, sorry.");
  return NULL;
}
#endif
