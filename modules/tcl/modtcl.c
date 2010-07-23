/*
 * Copyright (C) 2000-2010  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
#include "init.h"
#include "modtcl.h"
#include "direct.h"
#include "conversion.h"

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
  { "evnt",	NULL, 0 },
  { "sent",	NULL, 0 },
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

#ifdef HAVE_ICONV
static conversion_t *TclUTFConv;
#endif

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
#ifndef HAVE_TCL8X
  char var[TCL_RESULT_SIZE];

  if (sz > sizeof(var))
    sz = sizeof(var);
  strfcpy (var, res, sz);
  Tcl_SetResult (tcl, var, TCL_VOLATILE);
#else
  Tcl_SetObjResult (tcl, Tcl_NewStringObj ((char *)res, sz));
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
#endif

static int _tcl_interface (char *, int, char **);

/* ---------------------------------------------------------------------------
 * Calls from TCL to anywhere.
 */

/* functions of core/modules */
static int _tcl_call_function (ClientData func, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  char string[LONG_STRING];
  char *c, *cs = string;
  size_t s, ss = sizeof(string) - 1;
  int i = 0;
  Function f = (Function)func;

  while (argc && s)			/* make a string from argv[] */
  {
    c = ArgString (argv[i++], &s);
    if (cs != string)
    {
      *cs++ = ' ';
      ss--;
    }
    if (s > ss)
      s = ss;
    // TODO: do quote if arg has spaces?
    memcpy (cs, c, s);
    cs += s;
    ss -= s;
  }
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
	a++;

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
	a++;

			/* bind <type> <attr> key [cmd] */
static int _tcl_bind (ClientData cd, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  tcl_bindtable *tbt;
  char *c, *fn;
  size_t s;
  userflag gf, cf;
  char buf[32];

  if (argc < 3 || argc > 4)		/* check for number of params */
    return _tcl_errret (tcl, "bad number of parameters.");
  c = ArgString (argv[0], &s);		/* find <type> in list */
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
  c = ArgString (argv[1], &s);		/* calculate attr(s) */
  gf = 0;
  _tcl_togflag (c, s, gf);
  cf = 0;
  _tcl_tocflag (c, s, cf);
  c = ArgString (argv[2], &s);		/* it's key/mask now */
  if (argc == 3) /* if no command name then find and return binding name */
  {
    bindtable_t *bt = Add_Bindtable (tbt->name, B_UNDEF);
    binding_t *bind = Check_Bindtable (bt, c, gf, cf | U_EQUAL, NULL);

    if (bind && bind->name && bind->func == &_tcl_interface)
      ResultString (tcl, bind->name, strlen (bind->name));
    return TCL_OK;			/* how to notify we have result? */
  }
  fn = ArgString (argv[3], &s);
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

  if (argc != 4)			/* check for number of params */
    return _tcl_errret (tcl, "bad number of parameters.");
  c = ArgString (argv[0], &s);		/* find <type> in list */
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
  c = ArgString (argv[3], &s);		/* it's command name now */
  Delete_Binding (tbt->name, &_tcl_interface, c);
  return TCL_OK;
}

			/* send_request <to> <type> <mode> text */
static int _tcl_send_request (ClientData cd, Tcl_Interp *tcl, int argc, TCLARGS argv[])
{
  return TCL_ERROR; // not ready yet
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
    dprint (3, "tcl:_trace_int: deleted %s",
	    Tcl_GetVar2 (tcl, name1, name2, TCL_GLOBAL_ONLY));
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
#else
    if (Tcl_GetInt (tcl,
		NONULL(Tcl_GetVar2 (tcl, name1, name2, TCL_GLOBAL_ONLY)),
		&i) == TCL_ERROR)
      return tcl->result;
    *(long int *)vardata->data = (long int)i;
#endif
  }
  // TODO: TCL_TRACE_READS
  else
    ERROR ("tcl:_trace_int: unknown flags %d", flags);
  return NULL;
}

static char *_trace_bool (ClientData data, Tcl_Interp *interp,
			  char *name1, char *name2, int flags)
{
#ifndef HAVE_TCL8X
  char value[32];
#endif
  int i;

  if (flags & TCL_TRACE_UNSETS)	/* deleting it */
  {
    dprint (3, "tcl:_trace_bool: deleted %s",
	    Tcl_GetVar2 (interp, name1, name2, TCL_GLOBAL_ONLY));
#ifdef HAVE_TCL8X
    Tcl_DecrRefCount (vardata->name);
#endif
    FREE (&data);
  }
  else if (flags & TCL_TRACE_WRITES)
  {
#ifdef HAVE_TCL8X
    if (Tcl_GetBooleanFromObj (interp,
		Tcl_ObjGetVar2 (interp, vardata->name, NULL, TCL_GLOBAL_ONLY),
		&i) == TCL_ERROR)
      return Tcl_GetStringResult (interp);
#else
    if (Tcl_GetBoolean (interp,
		NONULL(Tcl_GetVar2 (interp, name1, name2, TCL_GLOBAL_ONLY)),
		&i) == TCL_ERROR)
      return interp->result;
#endif
    *(short *)((tcl_data *)data)->data = (short)i;
  }
  // TODO: TCL_TRACE_READS
  else
    ERROR ("tcl:_trace_bool: unknown flags %d", flags);
  return NULL;
}

static char *_trace_str (ClientData data, Tcl_Interp *interp,
			 char *name1, char *name2, int flags)
{
  int i;
  char *s;

  if (flags & TCL_TRACE_UNSETS)	/* deleting it */
  {
    dprint (3, "tcl:_trace_str: deleted %s",
	    Tcl_GetVar2 (interp, name1, name2, TCL_GLOBAL_ONLY));
#ifdef HAVE_TCL8X
    Tcl_DecrRefCount (vardata->name);
#endif
    FREE (&data);
  }
  else if (flags & TCL_TRACE_WRITES)
  {
#ifdef HAVE_TCL8X
    if (!(s = Tcl_GetStringFromObj (Tcl_ObjGetVar2 (interp,
	((tcl_data *)data)->name, NULL, TCL_GLOBAL_ONLY), &i)))
      return Tcl_GetStringResult (interp);
#else
    if (!(s = Tcl_GetVar2 (interp, name1, name2, TCL_GLOBAL_ONLY)))
      return interp->result;
    i = safe_strlen (s);
#endif
    if (i >= 0 && i < ((tcl_data *)data)->len)
    {
      strfcpy ((char *)((tcl_data *)data)->data, s, i + 1);
      return NULL;
    }
    i = ((tcl_data *)data)->len - 1;
    strfcpy ((char *)((tcl_data *)data)->data, s, i + 1);
  }
  // TODO: TCL_TRACE_READS
  else
    ERROR ("tcl:_trace_str: unknown flags %d", flags);
  return NULL;
}

static char *_trace_stat (ClientData data, Tcl_Interp *interp,
			  char *name1, char *name2, int flags)
{
  if (flags & TCL_TRACE_UNSETS)	/* deleting it */
  {
    dprint (3, "tcl:_trace_stat: deleted %s",
	    Tcl_GetVar2 (interp, name1, name2, TCL_GLOBAL_ONLY));
#ifdef HAVE_TCL8X
    Tcl_DecrRefCount (vardata->name);
#endif
    FREE (&data);
  }
  else if (flags & TCL_TRACE_WRITES)
    // TODO: reset it in TCL
    return "this variable is read only";
  return NULL;
}
#undef vardata

/* ---------------------------------------------------------------------------
 * Calls from anywhere to TCL.
 */

BINDING_TYPE_register(tcl_register_var);
static int tcl_register_var (const char *name, void *ptr, size_t s)
{
  tcl_data *data;

  data = safe_calloc (1, sizeof(tcl_data));
  data->data = ptr;
  data->len = s;
#ifdef HAVE_TCL8X
  data->name = Tcl_NewStringObj ((char *)name, safe_strlen (name));
  Tcl_IncrRefCount (data->name);
#endif
  switch (s)
  {
    case 0:	/* integer */
#ifdef HAVE_TCL8X
      Tcl_ObjSetVar2 (Interp, data->name, NULL,
		      Tcl_NewLongObj (*(long int *)data->data),
		      TCL_GLOBAL_ONLY);
#else
      snprintf (value, sizeof(value), "%ld", *(long int *)data->data);
      Tcl_SetVar (Interp, name, value, TCL_GLOBAL_ONLY);
#endif
      Tcl_TraceVar (Interp, (char *)name, TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
		    &_trace_int, (ClientData)data);
      break;
    case 1:	/* boolean */
#ifdef HAVE_TCL8X
      Tcl_ObjSetVar2 (Interp, data->name, NULL,
		      Tcl_NewBooleanObj ((int)*(short *)data->data),
		      TCL_GLOBAL_ONLY);
#else
      snprintf (value, sizeof(value), "%hd", *(short *)data->data);
      Tcl_SetVar (Interp, name, value, TCL_GLOBAL_ONLY);
#endif
      Tcl_TraceVar (Interp, (char *)name, TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
		    &_trace_bool, (ClientData)data);
      break;
    case 2:	/* read-only */
#ifdef HAVE_TCL8X
      Tcl_ObjSetVar2 (Interp, data->name, NULL,
		      Tcl_NewStringObj (data->data, safe_strlen (data->data)),
		      TCL_GLOBAL_ONLY);
#else
      Tcl_SetVar (Interp, name, data, TCL_GLOBAL_ONLY);
#endif
      Tcl_TraceVar (Interp, (char *)name, TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
		    &_trace_stat, (ClientData)data);
      break;
    default:	/* string */
#ifdef HAVE_TCL8X
      Tcl_ObjSetVar2 (Interp, data->name, NULL,
		      Tcl_NewStringObj (data->data, safe_strlen (data->data)),
		      TCL_GLOBAL_ONLY);
#else
      Tcl_SetVar (Interp, name, data->data, TCL_GLOBAL_ONLY);
#endif
      Tcl_TraceVar (Interp, (char *)name, TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
		    &_trace_str, (ClientData)data);
  }
  dprint (3, "tcl:registered variable %s.", name);
  return 1;
}

BINDING_TYPE_unregister(tcl_unregister_var);
static int tcl_unregister_var (const char *name)
{
  if (Tcl_UnsetVar (Interp, (char *)name, TCL_GLOBAL_ONLY) == TCL_OK)
    return 1;
  ERROR ("tcl:unregister variable %s failed: %s", name,
	 Tcl_GetStringResult (Interp));
  return 0;
}

BINDING_TYPE_function(tcl_register_func);
static int tcl_register_func (const char *name, int (*func) (char *))
{
#ifdef HAVE_TCL8X
  if (Tcl_CreateObjCommand
#else
  if (Tcl_CreateCommand
#endif
	(Interp, (char *)name, &_tcl_call_function, (ClientData)func, NULL) == TCL_OK)
   return 1;
  return 0;		/* error */
}

BINDING_TYPE_unfunction(tcl_unregister_func);
static int tcl_unregister_func (const char *name)
{
  if (Tcl_DeleteCommand (Interp, (char *)name) == TCL_OK)
    return 1;
  ERROR ("tcl:unregister function %s failed: %s", name,
	 Tcl_GetStringResult (Interp));
  return 0;		/* error */
}

BINDING_TYPE_script(script_tcl);
static int script_tcl (char *filename)
{
  if (Tcl_EvalFile (Interp, filename) == TCL_OK)
    return 1;				/* success! */
  ERROR ("tcl:execution of \"%s\" failed: %s", filename,
	 Tcl_GetStringResult (Interp));
  return 0;
}

BINDING_TYPE_dcc(dc_tcl);
static int dc_tcl (peer_t *from, char *args)
{
  char *c;
#ifdef HAVE_ICONV
  char str[LONG_STRING];
  size_t ss;

  if (!args)
    return 0;
  c = str;
  ss = Undo_Conversion (TclUTFConv, &c, sizeof(str) - 1, args, strlen(args));
  c[ss] = 0;				/* terminate the line */
#else
  if (!(c = args))
    return 0;
#endif
  Tcl_ResetResult (Interp);		/* reset it before run */
  if (Tcl_Eval (Interp, c) == TCL_OK)	/* success! */
  {
    if ((c = Tcl_GetStringResult (Interp)))
    {
#ifdef HAVE_ICONV
      args = c;
      c = str;
      ss = Do_Conversion (TclUTFConv, &c, sizeof(str) - 1, args, strlen(args));
      c[ss] = 0;
#endif
      New_Request (from->iface, 0, "TCL: result was: %s", c);
    }
  }
  else
    New_Request (from->iface, 0, "TCL: execution failed: %s",
		Tcl_GetStringResult (Interp));
  return 1;
}

/* interpreter interface for everyone */
static int _tcl_interface (char *fname, int argc, char *argv[])
{
  int i;
#ifdef HAVE_TCLEVALOBJV
  Tcl_Obj *objv[8];			/* I hope it's enough */
#endif

  if (!fname || !*fname)		/* nothing to do */
    return 0;
  if (!safe_strcmp ("-", fname))	/* they asked my name */
  {
    BindResult = "tcl";
    return 1;
  }
  Tcl_ResetResult (Interp);
  /* now it's time to call TCL */
#ifdef HAVE_TCLEVALOBJV
  objv[0] = Tcl_NewStringObj (fname, safe_strlen (fname));
  if (argc > 6)
    argc = 6;
  for (i = 0; i < argc; i++)
    objv[i + 1] = Tcl_NewStringObj (argv[i], safe_strlen (argv[i]));
  i = Tcl_EvalObjv (Interp, argc + 1, objv, TCL_GLOBAL_ONLY);
#else
  switch (argc)
  {
    case 0:
      i = Tcl_VarEval (Interp, fname, NULL);
      break;
    case 1:
      i = Tcl_VarEval (Interp, fname, argv[0], NULL);
      break;
    case 2:
      i = Tcl_VarEval (Interp, fname, argv[0], argv[1], NULL);
      break;
    case 3:
      i = Tcl_VarEval (Interp, fname, argv[0], argv[1], argv[2], NULL);
      break;
    case 4:
      i = Tcl_VarEval (Interp, fname, argv[0], argv[1], argv[2], argv[3], NULL);
      break;
    case 5:
      i = Tcl_VarEval (Interp, fname, argv[0], argv[1], argv[2], argv[3], argv[4], NULL);
      break;
    default:
      i = Tcl_VarEval (Interp, fname, argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], NULL);
      break;
  }
#endif
  if (i == TCL_OK)			/* setting BindResult if all went OK */
  {
    BindResult = Tcl_GetStringResult (Interp);
    return 1;
  }
  Add_Request (I_LOG, "*", F_WARN, "TCL: executing %s returned error: %s",
	       fname, Tcl_GetStringResult (Interp));
  return 0;
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log,
 *  S_REG - register everything.
 */
static int module_signal (INTERFACE *iface, ifsig_t sig)
{
  tcl_bindtable *tbt;

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
      Tcl_DeleteInterp (Interp);	/* stop interpreter */
      Interp = NULL;
#ifdef HAVE_ICONV
      Free_Conversion (TclUTFConv);
#endif
      Delete_Help ("tcl");
      iface->ift |= I_DIED;		/* done */
    case S_REG:
      Add_Request (I_INIT, "*", F_REPORT, "module tcl");
      break;
    case S_REPORT:
      // TODO!
    default: ;
  }
  return 0;
}

/*
 * this function called when you load a module.
 * Input: parameters string args.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
Function ModuleInit (char *args)
{
  char t[sizeof(ifsig_t)] = {S_REG};

  /* kill old interpreter */
  if (Interp)
    Tcl_DeleteInterp (Interp);
  /* init Tcl interpreter */
  Interp = Tcl_CreateInterp();
#ifdef HAVE_TCL_SETSYSTEMENCODING
  if (*Charset && Tcl_SetSystemEncoding (Interp, Charset) != TCL_OK)
    Add_Request (I_LOG, "*", F_BOOT, "Warning: charset %s unknown for Tcl",
		 Charset);
#endif
#ifdef HAVE_ICONV
  TclUTFConv = Get_Conversion ("UTF-8");
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
  Add_Request (I_MODULE | I_INIT, "*", F_SIGNAL, t);
  Add_Help ("tcl");
  return ((Function)&module_signal);
}
#else /* not HAVE_TCL */
Function ModuleInit (char *args)
{
  ERROR ("Cannot run TCL, there is not any, sorry.");
  return NULL;
}
#endif
