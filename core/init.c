/*
 * Copyright (C) 1999-2002  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * Main bot variables and functions init and scripts registering and export.
 * Bindtables: register unregister function unfunction script
 */

#include "foxeye.h"

#include <pthread.h>
#include <signal.h>
#include <ctype.h>

#include "dcc.h"
#include "tree.h"
#include "users.h"

#ifndef HAVE_SIGACTION
# define sigaction sigvec
#ifndef HAVE_SA_HANDLER
# define sa_handler sv_handler
# define sa_mask sv_mask
# define sa_flags sv_flags
#endif
#endif /* HAVE_SIGACTION */

/* ----------------------------------------------------------------------------
 * bindtables functions
 */

static pthread_mutex_t BindLock = PTHREAD_MUTEX_INITIALIZER;

static BINDTABLE *Tables = NULL;

BINDTABLE *Add_Bindtable (const char *name, bindtable_t type)
{
  BINDTABLE *bt;

  if (Tables == NULL)
    bt = Tables = safe_calloc (1, sizeof(BINDTABLE));
  else
  {
    for (bt = Tables; bt; bt = bt->next)
    {
      if (!safe_strcmp (bt->name, name))
	break;
      if (!bt->next)
      {
	bt->next = safe_calloc (1, sizeof(BINDTABLE));
	bt = bt->next;
	break;
      }
    }
  }
  if (!bt->name)
    bt->name = safe_strdup (name);
  bt->type = type;
  dprint (1, "binds: added bindtable with name \"%s\"", name);
  return bt;
}

static BINDTABLE *Try_Bindtable (const char *name, int force_add)
{
  BINDTABLE *bt = Tables;

  for (; bt; bt = bt->next)
    if (!safe_strcmp (bt->name, name))
      break;
  if (bt || !force_add)
    return bt;
  return Add_Bindtable (name, B_MASK);	/* default type */
}

BINDING *Add_Binding (const char *table, const char *mask, userflag gf,
		      userflag cf, Function func)
{
  BINDTABLE *bt = Try_Bindtable (table, 1);
  BINDING *bind = safe_calloc (1, sizeof(BINDING));
  BINDING *b, *last = NULL;

  bind->key = safe_strdup (mask);
  bind->gl_uf = gf;
  bind->ch_uf = cf;
  bind->name = NULL;
  bind->func = func;
  pthread_mutex_lock (&BindLock);
  if (bt->type == B_UNIQ && (!mask || !*mask))
  {
    bind->nbind = bt->lr;
    bt->lr = bind;
    pthread_mutex_unlock (&BindLock);
    dprint (1, "binds: added last resort binding to bindtable \"%s\"", table);
    return bind;
  }
  for (b = bt->bind; b; b = b->next)
  {
    if (!safe_strcasecmp (b->key, mask))	/* the same mask found! */
    {
      if (bind->func == func && b->gl_uf == gf && b->ch_uf == cf)
      {
	FREE (&bind->key);			/* duplicate binding */
	FREE (&bind);
	pthread_mutex_unlock (&BindLock);
	return NULL;
      }
      if (bt->type == B_UNIQ || bt->type == B_UNIQMASK)
      {
	bind->nbind = b;
	b = b->next;
	break;
      }
    }
    last = b;
  }
  bind->next = b;
  if (last)
    last->next = bind;
  else
    bt->bind = bind;
  pthread_mutex_unlock (&BindLock);
  dprint (1, "binds: added binding to bindtable \"%s\" with mask \"%s\"",
	  table, mask);
  return bind;
}

void Delete_Binding (const char *table, Function func)
{
  BINDTABLE *bt = Try_Bindtable (table, 0);
  BINDING *bind, *b, *last = NULL, *next;

  if (bt == NULL)
    return;
  for (b = bt->lr; b; )			/* first pass: ckeck last resort */
  {
    if (b->func == func)
    {
      if (last)
	last->nbind = bind = b->nbind;
      else
	bt->lr = bind = b->nbind;
      dprint (1, "binds: deleting last resort binding from bindtable \"%s\"",
	      table);
      pthread_mutex_lock (&BindLock);
      FREE (&b->key);
      FREE (&b);
      pthread_mutex_unlock (&BindLock);
      b = bind;
    }
    else
    {
      last = b;
      b = b->nbind;
    }
  }
  last = NULL;
  for (b = bt->bind; b; )		/* second pass: check list */
  {
    for (bind = b, next = NULL; bind; )
    {
      if (bind->func == func)
      {
	dprint (1, "binds: deleting binding from bindtable \"%s\" with mask \"%s\"",
		table, bind->key);
	pthread_mutex_lock (&BindLock);
	FREE (&bind->key);
	if (next)
	{
	  next->nbind = bind->nbind;
	  next = bind;
	}
	else
	{
	  b = bind->nbind;
	  if (!b)
	  {
	    if (!last)
	      bt->bind = bind->next;
	    else
	      last->next = bind->next;
	  }
	  else
	  {
	    b->next = bind->next;
	    if (!last)
	      bt->bind = b;
	    else
	      last->next = b;
	  }
	}
	FREE (&bind);
	pthread_mutex_unlock (&BindLock);
      }
      else
	next = bind;
      if (next)
	bind = next->nbind;
      else
	bind = b;
    }
    if (b)
      last = b;
    if (last)
      b = last->next;
    else
      b = bt->bind;
  }
}

BINDING *Check_Bindtable (BINDTABLE *bt, const char *str, userflag gf,
			  userflag cf, BINDING *bind)
{
  int i = 0;
  BINDING *b;
  char buff[LONG_STRING];
  register char *ch = buff;
  register const char *s = NONULL(str);
  char cc = ' ';
  size_t sz;

  if (bt == NULL)
    return NULL;
  if (bt->type == B_MASK || bt->type == B_UNIQMASK)
    cc = 0;
  else if (bt->type == B_MATCHCASE)
    i++;
  for (; *s && *s != cc && ch < &buff[sizeof(buff)-1]; ch++, s++)
  {
    if (i)
      *ch = *s;
    else
      *ch = tolower (*s);
  }
  *ch = 0;
  sz = safe_strlen (buff);
  pthread_mutex_lock (&BindLock);
  b = bt->bind;
  if (bind)		/* check if binding bind exist */
  {
    for (; b && b != bind; b = b->next);
    if (b) b = b->next;
    bind = NULL;
  }
  for (i = 0; b; b = b->next)
  {
    if ((b->gl_uf & gf) != b->gl_uf && (b->ch_uf & cf) != b->ch_uf)
      continue;
    switch (bt->type)
    {
      case B_MATCHCASE:
      case B_KEYWORD:
      case B_UNIQ:
	if (!safe_strcmp (b->key, buff))	/* exact matching */
	  i = 1;
	else if (bt->type == B_UNIQ && !safe_strncmp (b->key, buff, sz))
	{
	  if (bind)
	    i = -1;		/* more than one matched, wait to exact */
	  else
	    bind = b;		/* that is matched to completion */
	}
	break;
      case B_MASK:
      case B_UNIQMASK:
	i = match (b->key, str) + 1;
	break;
    }
    if (i > 0)
      break;
  }
  pthread_mutex_unlock (&BindLock);
  if (bt->type == B_UNIQ && !i)
    b = bind;			/* completion */
  if (b)
    dprint (3, "binds: bindtable \"%s\" string \"%s\", flags 0x%x/0x%x, found mask \"%s\"",
	    bt->name, str, gf, cf, b->key);
  else if (bt->type == B_UNIQ && bt->lr)
  {
    dprint (3, "binds: bindtable \"%s\" string \"%s\", using last resort",
	    bt->name, str);
    return bt->lr;
  }
  return b;
}

#define __INIT_C 1
/* define functions & variables first */
#include "init.h"

int RunBinding (BINDING *bind, const uchar *uh, char *fst, char *sec, int num,
		char *last)
{
  char uhost[STRING] = "";
  char n[16];
  char *a[6];
  register int i = 0;

  if (!bind || !bind->name || !bind->func)	/* checking... */
    return 0;
  dprint (4, "init:RunBinding: %s %s %s %s %d %s", bind->name,
	  NONULL((char *)uh), NONULL(fst), NONULL(sec), num, NONULL(last));
  BindResult = NULL;				/* clear result */
  if (uh)
  {
    strfcpy (uhost, (char *)uh, sizeof(uhost));	/* nick!user@host -> */
    a[0] = uhost;				/* -> nick user@host */
    if ((a[1] = safe_strchr (uhost, '!')))
      *(a[1]++) = 0;
    else
      a[1] = "*";
    i = 2;
  }
  if (fst && *fst)				/* NONULL */
    a[i++] = fst;
  if (sec && *sec)				/* NONULL */
    a[i++] = sec;
  if (num >= 0)					/* below 0 are ignored */
  {
    snprintf (n, sizeof(n), "%d", num);
    a[i++] = n;
  }
  if (last && *last)				/* NONULL */
    a[i++] = last;
  i = bind->func (bind->name, i, a);		/* int func(char *,int,char **) */
  if (i)					/* return 0 or 1 only */
    i = 1;
  return i;
}

/* ----------------------------------------------------------------------------
 * Confirm() implementation
 */

typedef struct
{
  pthread_mutex_t mutex;
  bool res;
} confirm_t;

static iface_t confirm_sig (INTERFACE *iface, ifsig_t sig)
{
  pthread_mutex_lock (&((confirm_t *)iface->data)->mutex);
  ((confirm_t *)iface->data)->res &= 1;		/* reset to FALSE/TRUE */
  pthread_mutex_unlock (&((confirm_t *)iface->data)->mutex);
  return I_DIED;
}

static REQUEST *confirm_req (INTERFACE *iface, REQUEST *req)
{
  pthread_mutex_lock (&((confirm_t *)iface->data)->mutex);
  if (req && req->string[0] == 'y')
    ((confirm_t *)iface->data)->res = TRUE;
  else
    ((confirm_t *)iface->data)->res = FALSE;
  pthread_mutex_unlock (&((confirm_t *)iface->data)->mutex);
  iface->iface = I_DIED;			/* we got answer so can die */
  return NULL;
}

static pthread_mutex_t ConfirmLock = PTHREAD_MUTEX_INITIALIZER;
static unsigned short _confirm_num = 0;

bool Confirm (char *message, bool defl)
{
  INTERFACE *newif;
  INTERFACE *ui;
  confirm_t ct;
  char n[8];

  if (!(defl & 2))
    return defl;
  ct.res = defl;
  pthread_mutex_lock (&ConfirmLock);
  if ((ui = Find_Iface (I_MODULE, "ui")) == NULL)
  {
    pthread_mutex_unlock (&ConfirmLock);
    return (defl & 1);				/* reset to FALSE/TRUE */
  }
  pthread_mutex_init (&ct.mutex, NULL);
  snprintf (n, sizeof(n), "=%hu", _confirm_num);
  _confirm_num++;
  newif = Add_Iface (n, I_TEMP, &confirm_sig, &confirm_req, &ct);
  Set_Iface (newif);
  New_Request (ui, F_ASK, _("%s (y/n)?[%c] "), message,
	      (defl & 1) == TRUE ? 'y' : 'n');
  Unset_Iface();	/* newif */
  Unset_Iface();	/* ui */
  while (1) {
    pthread_mutex_lock (&ct.mutex);
    if (!(ct.res & 2))
    {
      pthread_mutex_unlock (&ct.mutex);
      break;
    }
    pthread_mutex_unlock (&ct.mutex);
  }
  pthread_mutex_unlock (&ConfirmLock);
  pthread_mutex_destroy (&ct.mutex);
  return ct.res;
}

/* ----------------------------------------------------------------------------
 * config generation
 */

/* config file interface when generating */
static INTERFACE *ConfigFileIface = NULL;
static FILE *ConfigFileFile = NULL;

static REQUEST *_cfile_req (INTERFACE *iface, REQUEST *req)
{
  if (req && req->string[0])
  {
    if (req->flag & F_REPORT)			/* from console */
      fprintf (ConfigFileFile, "%s\n\n", req->string);
    else					/* from help */
      fprintf (ConfigFileFile, "# %s\n", req->string);
  }
  return NULL;
}

static INTERFACE *Init = NULL;
static char _usage[MESSAGEMAX];

/*
 * Interface I_INIT:
 *   if F_REPORT then bounce to config file
 *   else store it in _usage[] - it was from console
 */
REQUEST *_config_req (INTERFACE *iface, REQUEST *req)
{
  register char *c;

  if (req)
  {
    if (req->flag & F_REPORT)
    {
      if (ConfigFileFile)
	return _cfile_req (ConfigFileIface, req);
      return NULL;
    }
    c = req->string;
    while (*c == ' ') c++;			/* ltrim it */
    if (*c)
      strfcpy (_usage, c, sizeof(_usage));
  }
  return NULL;
}

static char *_quote_expand (char *ptr)
{
  register char *c;

  if (strchr (ptr, ' ') == NULL)	/* nothing to do */
    return ptr;
  _usage[0] = '"';
  for (c = _usage+1; *ptr && c < &_usage[sizeof(_usage)-2]; )
  {
    if (*ptr == '"')			/*  "  ->  ""  */
    {
      if (c == &_usage[sizeof(_usage)-3])
	break;
      *c++ = '"';
    }
    *c++ = *ptr++;
  }
  *c++ = '"';
  *c = 0;				/* terminate string */
  return _usage;
}

static void Get_ConfigFromConsole (const char *name, void *ptr, size_t s)
{
  INTERFACE *cons = Find_Iface (I_CONSOLE, NULL);
  int prompt = 1;

  Unset_Iface();
  if (!Init)
    return;
  if (cons && !(cons->iface & I_DIED)) do
    {
      if (prompt)
      {
	Get_Help ("set", name, Init, -1, -1, NULL, NULL, 0);
	Set_Iface (Init);
	while (Get_Request());		/* empty the queue and get help :) */
	if (_usage[0] != 's')		/* help not found, OK */
	  snprintf (_usage, sizeof(_usage), "set %s", name);
	if (s > 1)				/* string variable */
	  New_Request (cons, 0, "%s [%s]: ", _usage, (char *)ptr);
	else if (!s)			/* numeric variable */
	  New_Request (cons, 0, "%s [%ld]: ", _usage, *(long int *)ptr);
	else				/* boolean variable */
	  New_Request (cons, 0, "%s [%s%s]: ", _usage,
					(*(bool *)ptr & ASK) ? "ask-" : "",
					(*(bool *)ptr & 1) ? "on" : "off");
	Unset_Iface();
	prompt = 0;
      }
      Set_Iface (cons);			/* print out one line */
      Get_Request();
      Unset_Iface();
      _usage[0] = 0;
      Set_Iface (Init);			/* get a line from console */
      Get_Request();
      Unset_Iface();
      if (!strcmp (_usage, "?"))	/* "?" entered - print help */
      {
	Get_Help ("set", name, cons, -1, -1, NULL, "\n", 2);
	prompt = 1;
      }
      else if (_usage[0])
      {
	if (_usage[0] != '\n')		/* just "Enter" not was pressed */
	{
	  if (s > 1)			/* string variable entered */
	    strfcpy ((char *)ptr, _usage, s);
	  else if (!s)			/* numeric variable entered */
	    *(long int *)ptr = strtol (_usage, NULL, 10);
	  else if ((*(bool *)ptr & CAN_ASK) &&	/* boolean variable entered */
		   (!strcasecmp (_usage, "ask-yes") ||
		   !strcasecmp (_usage, "ask-on")))
	    *(bool *)ptr = TRUE | ASK | CAN_ASK;
	  else if ((*(bool *)ptr & CAN_ASK) &&
		   (!strcasecmp (_usage, "ask-no") ||
		   !strcasecmp (_usage, "ask-off")))
	    *(bool *)ptr = FALSE | ASK | CAN_ASK;
	  else if (!strcasecmp (_usage, "yes") ||
		   !strcasecmp (_usage, "on"))
	    *(bool *)ptr = TRUE | (*(bool *)ptr & CAN_ASK);
	  else
	    *(bool *)ptr = FALSE | (*(bool *)ptr & CAN_ASK);
	}
	break;
      }
    } while (!(cons->iface & I_DIED));
  if (ConfigFileIface)
  {
    Get_Help ("set", name, ConfigFileIface, -1, -1, NULL, NULL, 1);
    if (s > 1)
      New_Request (ConfigFileIface, F_REPORT, "set %s %s", name,
		   _quote_expand ((char *)ptr));
    else if (!s)
      New_Request (ConfigFileIface, F_REPORT, "set %s %ld", name,
		   *(long int *)ptr);
    else if ((*(bool *)ptr & 1) == TRUE)
      New_Request (ConfigFileIface, F_REPORT, "set %s %son", name,
		   (*(bool *)ptr & ASK) ? "ask-" : "");
    else
      New_Request (ConfigFileIface, F_REPORT, "set %s %soff", name,
		   (*(bool *)ptr & ASK) ? "ask-" : "");
    Set_Iface (ConfigFileIface);
    while (Get_Request());		/* write file */
    Unset_Iface();
  }
}

static int Start_FunctionFromConsole
		(const char *name, int (*func)(const char *), const char *msg)
{
  INTERFACE *cons = Find_Iface (I_CONSOLE, NULL);

  Unset_Iface();
  if (!Init || !cons || (cons->iface & I_DIED))
    return 0;
  /* get function parameters */
  Set_Iface (Init);
  New_Request (cons, 0, "add %s (%s)? []: ", name, msg);
  Unset_Iface();
  do
  {
    Set_Iface (cons);			/* print out one line */
    Get_Request();
    Unset_Iface();
    _usage[0] = 0;
    Set_Iface (Init);			/* get a line from console */
    Get_Request();
    Unset_Iface();
    if (_usage[0])
      break;
  } while (!(cons->iface & I_DIED));
  if (!_usage[0] || _usage[0] == '\n')	/* just "Enter" was pressed */
    return 0;
  /* start - check if valid */
  if ((*func) (_usage) != 0 && ConfigFileIface)
  {
    New_Request (ConfigFileIface, F_REPORT, "%s %s", name, _usage);
    Set_Iface (ConfigFileIface);
    while (Get_Request());		/* add to config file */
    Unset_Iface();
  }
  return 1;
}

/* ----------------------------------------------------------------------------
 * internal core tables: variables, operators(functions), formats, flood types
 */

BINDTABLE *BT_Reg = NULL;
BINDTABLE *BT_Unreg = NULL;
BINDTABLE *BT_Fn = NULL;
BINDTABLE *BT_Unfn = NULL;
BINDTABLE *BT_Script = NULL;

static NODE *VTree = NULL;		/* variables */
static NODE *STree = NULL;		/* operators */
static NODE *FTree = NULL;		/* formats */
static NODE *TTree = NULL;		/* flood types */

typedef struct
{
  void *data;
  size_t len;		/* 0 - int, 1 - bool, 2 - constant, >2 - string */
  char name[1] __attribute__ ((packed));
} VarData __attribute__ ((packed));

static int _add_var (const char *name, void *var, size_t s)
{
  VarData *data;

  if (O_GENERATECONF != FALSE && s != 2)	/* not read only */
    Get_ConfigFromConsole (name, var, s);
  if (Find_Key (VTree, name))			/* already registered */
    return 0;
  dprint (4, "init:_add_var: %s %u", name, (unsigned int)s);
  data = safe_calloc (1, sizeof(VarData) + safe_strlen(name));
  data->data = var;
  strcpy (data->name, name);
  data->len = s;
  if (!Insert_Key (&VTree, data->name, data, 1))	/* try unique name */
    return 1;
  FREE (&data);
  return 0;
}

static int _register_var (const char *name, void *var, size_t s)
{
  int i;
  BINDING *bind = NULL;

  if (!name || !var)
    return 0;
  i = _add_var (name, var, s);			/* static binding ;) */
  while ((bind = Check_Bindtable (BT_Reg, "*", -1, -1, bind)))
    if (!bind->name)				/* internal only */
      i |= bind->func (name, var, s);
  return i;
}

int RegisterInteger (const char *name, long int *var)
{
  return _register_var (name, var, 0);
}

int RegisterBoolean (const char *name, bool *var)
{
  return _register_var (name, var, 1);
}

int RegisterString (const char *name, void *str, size_t len, int ro)
{
  return _register_var (name, str, ro ? 2 : len);
}

static int _del_var (const char *name)
{
  VarData *data;

  if (!(data = Find_Key (VTree, name)))		/* not registered? */
    return 0;
  dprint (4, "init:_del_var: %s", name);
  Delete_Key (VTree, name, data);
  FREE (&data);
  return 1;
}

int UnregisterVariable (const char *name)
{
  int i = 0;
  BINDING *bind = NULL;

  i = _del_var (name);				/* static binding ;) */
  while ((bind = Check_Bindtable (BT_Unreg, "*", -1, -1, bind)))
    if (!bind->name)				/* internal only */
      i |= bind->func (name);
  return i;
}

typedef struct
{
  union {
    Function n;			/* command */
    short ld[2];		/* flood */
    char *mt;			/* format */
  } f;
  char name[1] __attribute__ ((packed));
} VarData2 __attribute__ ((packed));

static int
_add_fn (const char *name, int (*func)(const char *), const char *msg)
{
  int i;
  VarData2 *data;

  dprint (4, "init:_add_fn: %s", name);
  if (O_GENERATECONF != FALSE && msg)		/* ask for list */
    do {
      i = Start_FunctionFromConsole (name, func, msg);
    } while (i);
  data = safe_calloc (1, sizeof(VarData2) + safe_strlen(name));
  data->f.n = func;
  strcpy (data->name, name);
  if (!Insert_Key (&STree, name, data, 1))	/* try unique */
    return 1;
  FREE (&data);
  return 0;
}

static int _del_fn (const char *name)
{
  VarData2 *data;

  if (!(data = Find_Key (STree, name)))		/* not registered? */
    return 0;
  dprint (4, "init:_del_fn: %s", name);
  Delete_Key (STree, name, data);
  FREE (&data);
  return 1;
}

int
RegisterFunction (const char *name, int (*func)(const char *), const char *msg)
{
  int i;
  BINDING *bind = NULL;

  if (!name || !func)
    return 0;
  i = _add_fn (name, func, msg);		/* static binding ;) */
  while ((bind = Check_Bindtable (BT_Fn, "*", -1, -1, bind)))
    if (!bind->name)				/* internal only */
      i |= bind->func (name, func);
  return i;
}

int UnregisterFunction (const char *name)
{
  int i;
  BINDING *bind = NULL;

  i = _del_fn (name);				/* static binding ;) */
  while ((bind = Check_Bindtable (BT_Unfn, "*", -1, -1, bind)))
    if (!bind->name)				/* internal only */
      i |= bind->func (name);
  return i;
}

static short *_add_fl (const char *name, short n0, short n1)
{
  VarData2 *data = Find_Key (TTree, name);

  if (data)					/* already registered */
    return data->f.ld;
  dprint (4, "init:_add_fl: %s %hd:%hd", name, n0, n1);
  data = safe_calloc (1, sizeof(VarData2) + safe_strlen(name));
  data->f.ld[0] = n0;
  data->f.ld[1] = n1;
  strcpy (data->name, name);
  if (Insert_Key (&TTree, data->name, data, 1))	/* try unique name */
    bot_shutdown ("Internal error in _add_fl()", 8);
  return data->f.ld;
}

short *FloodType (const char *name)
{
  return _add_fl (name, 1, 1);			/* one event per one second */
}

static void _set_floods (void)
{
  LEAF *leaf = NULL;
  VarData2 *data;
  char *name, *c;
  INTERFACE *cons = Find_Iface (I_CONSOLE, NULL);

  Unset_Iface();
  while ((leaf = Next_Leaf (TTree, leaf, &name)))
  {
    data = leaf->s.data;
    if (cons && !(cons->iface & I_DIED))
    {
      Set_Iface (Init);
      New_Request (cons, 0, "set flood-type %s [%hd:%hd]: ", name,
		   data->f.ld[0], data->f.ld[1]);
      Unset_Iface();
      do
      {
	Set_Iface (cons);		/* print out one line */
	Get_Request();
	Unset_Iface();
	_usage[0] = 0;
	Set_Iface (Init);		/* get a line from console */
	Get_Request();
	Unset_Iface();
	if (_usage[0])
	{
	  if (_usage[0] != '\n')	/* just "Enter" not was pressed */
	  {				/* parse it... */
	    c = strchr (_usage, ':');
	    if (c && *(++c))
	    {
	      data->f.ld[0] = atoi (_usage);
	      data->f.ld[1] = atoi (c);
	    }
	  }
	  break;
	}
      } while (!(cons->iface & I_DIED));
    }
    if (ConfigFileIface)
    {
      New_Request (ConfigFileIface, F_REPORT, "flood-type %s %hd:%hd", name,
		   data->f.ld[0], data->f.ld[1]);
      Set_Iface (ConfigFileIface);
      while (Get_Request());		/* write file */
      Unset_Iface();
    }
  }
}

static void _add_fmt (const char *name, char *fmt)
{
  VarData2 *data;

  if (Find_Key (FTree, name))			/* already registered */
    return;
  dprint (4, "init:_add_fmt: %s", name);
  data = safe_calloc (1, sizeof(VarData2) + strlen(name));
  data->f.mt = fmt;
  strcpy (data->name, name);
  if (Insert_Key (&FTree, data->name, data, 1))	/* try unique name */
    FREE (&data);
  if (data && !fmt)
    data->f.mt = safe_calloc (1, FORMATMAX);
}

char *SetFormat (const char *name, char *val)
{
  VarData2 *data;

  _add_fmt (name, NULL);
  if ((data = Find_Key (FTree, name)) == NULL)	/* some error? */
    return NULL;
  strfcpy (data->f.mt, val, FORMATMAX);
  return data->f.mt;
}

/* ----------------------------------------------------------------------------
 * config file parsing
 */

static int ParseConfig (char *name, int ask)
{
  struct stat st;
  FILE *f;
  char *c = NULL;
  static char cmd[LONG_STRING];
  INTERFACE *cons = NULL;
  VarData2 *data;

  BindResult = cmd;
  snprintf (cmd, sizeof(cmd), "not permitted to load %s", name);
  if (lstat (name, &st) || !(st.st_mode & S_IRUSR))
    return -1;
  if (!(S_ISREG (st.st_mode)))			/* only regular file! */
    return -1;
  if ((f = fopen (name, "rb")))
  {
    if (!Init)
      ask = 0;
    if (ask)					/* find and lock */
      cons = Find_Iface (I_CONSOLE, NULL);
    while (fgets (cmd, sizeof(cmd), f))
    {
      c = cmd;
      while (*c == ' ') c++;
      if (*c == '#')				/* comment */
	continue;
      while (*c && *c != '\n' && *c != ' ') c++;
      if (*c)					/* delimit the command */
        *c++ = 0;
      while (*c == ' ') c++;			/* left trim */
      StrTrim (c);				/* right trim */
      if (!*c)					/* empty line */
	continue;
      if (!(data = Find_Key (STree, cmd)))	/* not found! */
      {
	c = NULL;
	break;
      }
      if (ask && cons && strcmp (cmd, "set"))	/* ask for all but set lines */
      {
	Set_Iface (Init);
	New_Request (cons, 0, "%s %s (y/n)? [y]: ", cmd, c);
	Unset_Iface();
	do
	{
	  Set_Iface (cons);			/* print out one line */
	  Get_Request();
	  Unset_Iface();
	  _usage[0] = 0;
	  Set_Iface (Init);			/* get a line from console */
	  Get_Request();
	  Unset_Iface();
	  if (cons->iface & I_DIED)
	    ask = 0;
	} while (!_usage[0] && ask);
	if (_usage[0] == 'n')			/* "n" entered - abort line */
	  continue;
      }
      if ((data->f.n) (c) == 0)			/* exec command */
      {
	c = NULL;				/* error? */
	break;
      }
    }
    if (cons)					/* unlock */
      Unset_Iface();
    fclose (f);
    if (c)
    {
      BindResult = NULL;
      return 0;
    }
  }
  snprintf (cmd, sizeof(cmd), "error in %s", name);
  return -1;
}

int Config_Exec (const char *cmd, const char *args)
{
  VarData2 *data;

  if (!cmd || !(data = Find_Key (STree, cmd)))	/* no such command */
    return 0;					/* silent ignore */
  dprint (4, "init:Config_Exec: %s %s", cmd, args);
  return data->f.n (NONULL(args));
}

static int _set (VarData *data, register char *val)
{
  bool ask;

  switch (data->len)
  {
    case 0:					/* long int */
      *(long int *)data->data = strtol (val, NULL, 10);
      break;
    case 1:					/* bool */
      if (*val == '"') val++;
      ask = (*(bool *)data->data & CAN_ASK);
      if (!strncasecmp (val, "ask-", 4))
      {
	if (ask)
	  ask |= ASK;
	val += 4;
      }
      if (!strncasecmp (val, "yes", 3) || !strncasecmp (val, "on", 2))
	*(bool *)data->data = ask | TRUE;
      else
	*(bool *)data->data = ask | FALSE;
      break;
    case 2:					/* r/o string */
      return 0;
    default:					/* string */
      NextWord_Unquoted ((char *)data->data, data->len, val);
  }
  return 1;
}

static ScriptFunction (cfg_set)		/* to config - by registering */
{
  char var[SHORT_STRING];
  VarData *data = NULL;
  register char *c;

//  if (args && !*args)
//    args = NULL;
//  if (args)
  if (args && *args)
  {
    /* any variable */
    for (c = var; *args && *args != ' ' && c < &var[sizeof(var)-1]; )
      *c++ = *args++;
    *c = 0;
    data = Find_Key (VTree, var);
    if (!data)
      return 0;
//    c = NextWord ((char *)args);
    return _set (data, NextWord ((char *)args));
//    if (*c)				/* is data empty or just "" ? */
//      return _set (data, c);
  }
  return 0;
}

static char *_Scripts_List = NULL;

static ScriptFunction (cfg_script)	/* to config - keep and store */
{
  BINDING *bind;
  register size_t ss;

  if (!args || !*args)
    return 0;
  bind = Check_Bindtable (BT_Script, args, -1, -1, NULL);
  if (!bind || bind->name || !bind->func (args))	/* internal only */
    return 0;
  ss = safe_strlen (_Scripts_List) + strlen (args) + 9;	/* "\nscript $args" */
  safe_realloc ((void **)&_Scripts_List, ss);
  strfcat (_Scripts_List, "\nscript ", ss);
  strfcat (_Scripts_List, args, ss);
  return 1;
}

static ScriptFunction (cfg_flood_type)	/* to config - by ask after all */
{
  char var[SHORT_STRING];
  VarData2 *data = NULL;
  register char *c, *c2;

//  if (args && !*args)
//    args = NULL;
//  if (args)
  if (args && *args)
  {
    for (c = var; *args && *args != ' ' && c < &var[sizeof(var)-1]; )
      *c++ = *args++;
    *c = 0;
    data = Find_Key (TTree, var);
    if (!data)
      return 0;
    c = NextWord ((char *)args);
    c2 = strchr (c, ':');
    if (c2 && *(++c2))
    {
      data->f.ld[0] = atoi (c);
      data->f.ld[1] = atoi (c2);
      return 1;
    }
  }
  return 0;
}

/* ----------------------------------------------------------------------------
 * formats file creating/parsing
 */

static int _load_formats (void)
{
  struct stat st;
  FILE *f;
  char *c = NULL;
  char fmt[LONG_STRING];
  VarData2 *data;

  if (!*FormatsFile || lstat (FormatsFile, &st) || !(st.st_mode & S_IRUSR))
    return -1;
  if (!(S_ISREG (st.st_mode)))			/* only regular file! */
    return -1;
  if ((f = fopen (FormatsFile, "rb")))
  {
    while (fgets (fmt, sizeof(fmt), f))
    {
      c = fmt;
      if (*c == '#')				/* comment */
	continue;
      while (*c && *c != '\n' && *c != ' ') c++;
      if (*c)					/* delimit the format name */
        *c++ = 0;
      while (*c == ' ') c++;			/* skip spaces */
      if (!*c)					/* empty line */
	continue;
      if ((data = Find_Key (FTree, fmt)))	/* if format found */
	NextWord_Unquoted (data->f.mt, FORMATMAX, c);
    }
    fclose (f);
    return 0;
  }
  return -1;
}

int Save_Formats (void)
{
  LEAF *leaf = NULL;
  struct stat st;
  FILE *f;
  char *name;

  if (!*FormatsFile || lstat (FormatsFile, &st) || !(st.st_mode & S_IWUSR))
    return -1;
  if (!(S_ISREG (st.st_mode)))			/* only regular file! */
    return -1;
  if ((f = fopen (FormatsFile, "wb")))
  {
    while ((leaf = Next_Leaf (FTree, leaf, &name)))
    {
      fprintf (f, "%s %s\n", name,
	       _quote_expand (((VarData2 *)leaf->s.data)->f.mt));
    }
    fclose (f);
    return 0;
  }
  return -1;
}

/* ----------------------------------------------------------------------------
 * Internal dcc bindings:
 * int func(DCC_SESSION *from, char *args)
 */

		/* .set [<variable>[ <value>]] */
static int dc_set (DCC_SESSION *dcc, char *args)
{
  char var[STRING];
  VarData *data = NULL;

  StrTrim (args);
  if (args && !*args)
    args = NULL;
  if (args)				/* any variable */
  {
    register char *c;

    for (c = var; *c && *c != ' ' && c < &var[sizeof(var)-1]; ) *c++ = *args++;
    *c = 0;
    data = Find_Key (VTree, var);
    if (!data)
      return 0;
    c = NextWord (args);
    if (*c && (dcc->uf & U_OWNER))
      _set (data, c);
    if (data->len == 0)
      New_Request (dcc->iface, 0, _("Current value of %s: %ld"), var,
		   *(long int *)data->data);
    else if (data->len == 1)
      New_Request (dcc->iface, 0, _("Current value of %s: %s%s"), var,
		   (*(bool *)data->data & ASK) ? "ask-" : "",
		   (*(bool *)data->data & 1) ? "on" : "off");
    else
      New_Request (dcc->iface, 0, _("Current value of %s: %s"), var,
		   (char *)data->data);
  }
  else					/* list of variables */
  {
    char *name;
    register char *c;
    LEAF *leaf = NULL;
    register size_t s;

    c = var;
    *c = 0;
    New_Request (dcc->iface, 0, _("List of variables:"));
    while ((leaf = Next_Leaf (VTree, leaf, &name)))
    {
      s = safe_strlen (name) + 16 - (c - var)%16;
      if (&c[s] > &var[72])
      {
	New_Request (dcc->iface, 0, var);
	c = var;
	strfcpy (var, name, sizeof(var));
      }
      else
      {
	do {
	  *c++ = ' ';
	} while ((c - var) % 16);
	*c = 0;
	strfcat (var, name, sizeof(var));
      }
      c = &var[strlen(var)];
    }
    if (*var)
      New_Request (dcc->iface, 0, var);
  }
  return 1;
}

		/* .fset [<format variable>[ <value>]] */
static int dc_fset (DCC_SESSION *dcc, char *args)
{
  char var[STRING];
  VarData2 *data = NULL;

  StrTrim (args);
  if (args && !*args)
    args = NULL;
  if (args)				/* any format */
  {
    register char *c;

    for (c = var; *c && *c != ' ' && c < &var[sizeof(var)-1]; ) *c++ = *args++;
    *c = 0;
    data = Find_Key (FTree, var);
    if (!data)
      return 0;
    if ((c = NextWord (args)))
      NextWord_Unquoted (data->f.mt, FORMATMAX, c);
    New_Request (dcc->iface, 0, _("Current format %s: %s"), var, data->f.mt);
  }
  else					/* list of formats */
  {
    char *name;
    register char *c;
    LEAF *leaf = NULL;
    register size_t s;

    c = var;
    *c = 0;
    New_Request (dcc->iface, 0, _("List of formats:"));
    while ((leaf = Next_Leaf (FTree, leaf, &name)))
    {
      s = safe_strlen (name) + 16 - (c - var)%16;
      if (&c[s] > &var[72])
      {
	New_Request (dcc->iface, 0, var);
	c = var;
	strfcpy (var, name, sizeof(var));
      }
      else
      {
	do {
	  *c++ = ' ';
	} while ((c - var) % 16);
	*c = 0;
	strfcat (var, name, sizeof(var));
      }
      c = &var[strlen(var)];
    }
    if (*var)
      New_Request (dcc->iface, 0, var);
  }
  return 1;
}

		/* .status [-a|<module name>] */
static int dc_status (DCC_SESSION *dcc, char *args)
{
  ifsig_t ifsig = S_REPORT;
  char buff[STRING];

  if (args && !*args)
    args = NULL;
  else if (args && !strcmp (args, "-a"))
    args = "*";
  printl (buff, sizeof(buff),
_("Universal network client %V.\n\
Operating system %s, hostname %@, started %*."),
	  0, NULL, hostname, Nick, NULL, 0L, 0, ctime (&StartTime));
  New_Request (dcc->iface, 0, buff);
  if (!args)
  {
    Status_Interfaces (dcc->iface);
    Status_Sheduler (dcc->iface);
    Status_Users (dcc->iface);
  }
  else
    Add_Request (I_MODULE, args, F_SIGNAL, (char *)&ifsig);
  return 1;
}

		/* .binds [-l|<name>|-a [<name>]] */
static int dc_binds (DCC_SESSION *dcc, char *args)
{
  int io;
  BINDTABLE *bt;
  BINDING *b;
  char *c;
  char flags[128];

  if (args && args[0] == '-')
  {
    if (args[1] == 'l')			/* list of bindtables */
    {
      New_Request (dcc->iface, 0, "Name                Type            Num of bindings");
      for (bt = Tables; bt; bt = bt->next)
      {
	io = 0;
	for (b = bt->bind; b; b = b->next)
	  io++;
	switch (bt->type)
	{
	  case B_MATCHCASE:
	    c = _("case-sensitive ");
	    break;
	  case B_KEYWORD:
	    c = _("full match     ");
	    break;
	  case B_MASK:
	    c = _("mask match     ");
	    break;
	  case B_UNIQ:
	    c = _("first key only ");
	    break;
	  case B_UNIQMASK:
	    c = _("first mask only");
	    break;
	  default:			/* can it be??? */
	    c = "";
	}
	New_Request (dcc->iface, 0, "%c%-18.18s %s %d", bt->lr ? '*' : ' ',
		     bt->name, c, io);
      }
      return 1;
    }
    else if (args[1] == 'a')		/* all bindings */
    {
      args = NextWord (args);
      io = 0;
    }
    else
      return 0;
  }
  else
    io = 1;
  if (args && *args)			/* only bindtable */
  {
    for (bt = Tables; bt; bt = bt->next)
      if (!safe_strcmp (bt->name, args))
	break;
    if (!bt)
      return 0;
    New_Request (dcc->iface, 0, "Key                     Flags   Interpreter     Command");
    for (b = bt->bind; b; b = b->next)
    {
      if (io && b->name)
	continue;
      userflagtostr (b->gl_uf, flags);
      if (b->ch_uf && !(b->ch_uf & U_ANY)) /* if this is set then denied */
      {
	strfcat (flags, "|", sizeof(flags));
	userflagtostr (b->ch_uf, &flags[strlen(flags)]);
      }
      if (b->name && b->func && b->func ("-", 0, NULL))
	New_Request (dcc->iface, 0, "%-23.23s %-7.7s %-15.15s %s", b->key,
		     flags, BindResult, b->name);
      else
	New_Request (dcc->iface, 0, "%-23.23s %s", b->key, flags);
    }
  }
  else for (bt = Tables; bt; bt = bt->next)
  {
    if (!bt->bind)
      continue;
    New_Request (dcc->iface, 0, _("  Bindtable %s:"), bt->name);
    New_Request (dcc->iface, 0, "Key                     Flags   Interpreter     Command");
    for (b = bt->bind; b; b = b->next)
    {
      if (io && b->name)
	continue;
      userflagtostr (b->gl_uf, flags);
      if (b->ch_uf && !(b->ch_uf & U_ANY)) /* if this is set then denied */
      {
	strfcat (flags, "|", sizeof(flags));
	userflagtostr (b->ch_uf, &flags[strlen(flags)]);
      }
      if (b->name && b->func && b->func ("-", 0, NULL))
	New_Request (dcc->iface, 0, "%-23.23s %-7.7s %-15.15s %s", b->key,
		     flags, BindResult, b->name);
      else
	New_Request (dcc->iface, 0, "%-23.23s %s", b->key, flags);
    }
  }
  return 1;
}

		/* .module -l */
		/* .module [-c|-d] <module name> */
static int dc_module (DCC_SESSION *dcc, char *args)
{
  if (!args || !*args)
    return 0;
  BindResult = _("Success");
  if (Config_Exec ("module", args) == 0)
    BindResult = _("Fail");
  New_Request (dcc->iface, 0, BindResult);
  return 1;
}

		/* .rehash */
static int dc_rehash (DCC_SESSION *dcc, char *args)
{
  ifsig_t i = S_FLUSH;

  New_Request (dcc->iface, 0, "Rehashing...");
  if (ParseConfig (Config, 0))
    bot_shutdown (BindResult, 3);
  Add_Request (-1, "*", F_SIGNAL, (char *)&i);    /* flush all interfaces */
  return 1;
}

		/* .restart */
static int dc_restart (DCC_SESSION *dcc, char *args)
{
  New_Request (dcc->iface, 0, "Restarting...");
  init();
  return -1;	/* don't log it :) */
}

		/* .die [<reason>] */
static void dc_die (DCC_SESSION *dcc, char *args)
{
  char message[MESSAGEMAX];
  static ifsig_t ifsig = S_TERMINATE;

  if (dcc)
  {
    snprintf (message, sizeof(message), _("Killed by %s%c %s"),
	      dcc->iface->name, (args && *args) ? ':' : '!', NONULL(args));
    BindResult = message;
  }
  else
    BindResult = NONULL(args);
	/* nice termination of modules (logs also, of cource) */
  Add_Request (I_MODULE, "*", F_SIGNAL, (char *)&ifsig);
	/* quiet termination of the core */
  bot_shutdown (message, 0);
  exit (0);
}

static void sighup_handler (int signo)
{
  ifsig_t i = S_FLUSH;

  Add_Request (I_LOG, "*", F_BOOT, "Got SIGHUP: rehashing...");
  Add_Request (-1, "*", F_SIGNAL, (char *)&i);	/* flush all interfaces */
}

static void sigint_handler (int signo)
{
  Set_Iface (NULL);			/* lock the dispatcher */
  Add_Request (I_LOG, "*", F_BOOT, "Got SIGINT: restarting...");
  init();				/* restart */
  Unset_Iface();			/* continue */
}

static void _init_all (void)
{
  /* register all variables and functions */
#define INIT_C 1
# include "init.h"
}

static ifsig_t _init_sig (INTERFACE *iface, ifsig_t sig)
{
  if (sig == S_REG)
    _init_all();
  return 0;
}

void init (void)
{
  int g = O_GENERATECONF;
  struct sigaction act;
  char new_path[PATH_MAX+FILENAME_LENGTH+2];
  char *msg;
  ifsig_t ifsig = S_TERMINATE;
  BINDTABLE *bt;
  BINDING *b2, *b;

//
// этап 0 - инициализация всего, что инициализируется в core
//
// перечень объектов core:
//  - команды "listen", "module"
//  - таблицы регистрации переменных, команд, форматов
//  - bindtables
//  - внутренние команды "set", "script"
//  - help "main", "set"
// объекты core с собственной инициализацией:
//  - sheduler
//  - listfile
// объекты core, не требующие инициализации:
//  - dcc support
//  - wtmp
//  - sockets
//  - main loop
//
  /* kill all modules */
  Add_Request (I_MODULE, "*", F_SIGNAL, (char *)&ifsig);
  /* I think I need to destroy trees ? */
  Destroy_Tree (&VTree, free);
  Destroy_Tree (&STree, free);
  /* empty all bindtables */
  for (bt = Tables; bt; bt = bt->next)
    while (bt->bind)
    {
      b = bt->bind;
      bt->bind = b->next;
      while (b->nbind)
      {
	b2 = b->nbind;
	b->nbind = b2->nbind;
	FREE (&b2->key);
	FREE (&b2);
      }
      FREE (&b->key);
      FREE (&b);
    }
  /* init sheduler to have current time */
  IFInit_Sheduler();
  /* add own bindtables and bindings */
  BT_Reg = Add_Bindtable ("register", B_MASK);
  BT_Unreg = Add_Bindtable ("unregister", B_MASK);
  BT_Fn = Add_Bindtable ("function", B_MASK);
  BT_Unfn = Add_Bindtable ("unfunction", B_MASK);
  BT_Script = Add_Bindtable ("script", B_UNIQMASK);

  _add_fn ("set", &cfg_set, NULL);		/* add operators */
  _add_fn ("script", &cfg_script, NULL);	/* but don't ask */
  _add_fn ("flood-type", &cfg_flood_type, NULL);
  /* init all */
  if ((msg = IFInit_DCC()))
    bot_shutdown (msg, 3);
  /* load help for variables and more */
  Add_Help ("set");
  Add_Help ("main");
//
// этап 1 - инициализация переменных и загрузка конфига, если не указан "-r"
//
  /* try to load old config if no "-r" */
  if (O_DEFAULTCONF == FALSE)
  {
    /* register all in core but don't ask! */
    O_GENERATECONF = FALSE;
    _init_all();
    /* try to load old config */
    if (!Config)
      bot_shutdown (_("Invalid configuration file!"), 3);
    else if (ParseConfig (Config, g))
      bot_shutdown (BindResult, 3);
    O_GENERATECONF = g;				/* ask all by next cycle */
  }
//
// этап 2 - реинициализация с запросом, если указан "-r" или "-g"
//          запросить значения всех переменных, в т.ч. из модулей по конфигу
//
  /* if generation is true, start new config */
  if (g != FALSE)
  {
    snprintf (new_path, sizeof(new_path), "%s.new", Config);
    ConfigFileFile = fopen (new_path, "w+");
    if (!ConfigFileFile)
      bot_shutdown (_("Cannot create configuration file."), 3);
    fprintf (ConfigFileFile, "#!%s\n# Generated by itself on %s\n", RunPath,
	     ctime (&Time));
    ConfigFileIface = Add_Iface (NULL, I_TEMP, NULL, &_cfile_req, NULL);
    ConfigFileIface->iface = I_TEMP;		/* create interface */
  }
  /* it can be recall of init so don't create another */
  if (!Init)
    Init = Add_Iface (NULL, I_INIT, &_init_sig, &_config_req, NULL);
  Init->iface &= ~I_LOCKED;			/* must be not locked! */
  if (g != FALSE || O_DEFAULTCONF != FALSE)
  {
    /* reregister all, ask, and write to config */
    ifsig = S_REG;
    O_GENERATECONF = TRUE;
    Add_Request (-1, "*", F_SIGNAL, (char *)&ifsig);
    _set_floods ();
    /* ask to include any new scripts */
    while (Start_FunctionFromConsole ("script", &cfg_script, "filename"));
    /* put all "script" calls to new config */
    fprintf (ConfigFileFile, "%s\n", _Scripts_List);
    FREE (&_Scripts_List);
    /* ending */
  }
  if ((msg = IFInit_Users()))		/* try to load listfile */
    bot_shutdown (msg, 3);
  if (!_load_formats())			/* try to load formats */
    Add_Request (I_LOG, "*", F_BOOT, "Loaded formats file \"%s\"", FormatsFile);
//
// постэтап - сохранение нового конфига, если указан "-g"
//
  if (g != FALSE)
  {
    fclose (ConfigFileFile);			/* save new config, mode 0700 */
    chmod (new_path, S_IRUSR | S_IWUSR | S_IXUSR);
    unlink (Config);				/* delete old config */
    rename (new_path, Config);
    ConfigFileIface->iface |= I_DIED;		/* delete interface */
    ConfigFileFile = NULL;
    ConfigFileIface = NULL;
  }
  /* Init have to get signal S_REG so don't kill it */
  Init->iface |= I_LOCKED;
  O_GENERATECONF = FALSE;
  O_DEFAULTCONF = FALSE;
  /* check if we going to finish:
      - we have no listen interface nor console nor module;
      - we got "-t" - just testing. */
  if (Find_Iface (I_LISTEN | I_CONSOLE | I_MODULE, NULL))
    Unset_Iface();
  else
    dc_die (NULL, "terminated: no interfaces to work");
  if (O_TESTCONF != FALSE)
    dc_die (NULL, NULL);
  /* init SIGINT (restart) and SIGHUP (rehash) handlers */
  act.sa_handler = &sigint_handler;
  sigemptyset (&act.sa_mask);
  act.sa_flags = 0;
  sigaction (SIGINT, &act, NULL);
  act.sa_handler = &sighup_handler;
  sigaction (SIGHUP, &act, NULL);
  Add_Binding ("dcc", "binds", U_MASTER, U_MASTER, (Function)&dc_binds);
  Add_Binding ("dcc", "module", U_OWNER, -1, (Function)&dc_module);
  Add_Binding ("dcc", "status", U_MASTER, -1, (Function)&dc_status);
  Add_Binding ("dcc", "fset", U_OWNER, -1, (Function)&dc_fset);
  Add_Binding ("dcc", "rehash", U_MASTER, -1, &dc_rehash);
  Add_Binding ("dcc", "restart", U_MASTER, -1, &dc_restart);
  Add_Binding ("dcc", "die", U_OWNER, -1, (Function)&dc_die);
  Add_Binding ("dcc", "set", U_MASTER, U_MASTER, &dc_set);
}
