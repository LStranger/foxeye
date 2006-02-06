/*
 * Copyright (C) 1999-2005  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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

#include "direct.h"
#include "tree.h"
#include "list.h"

#ifndef HAVE_SIGACTION
# define sigaction sigvec
#ifndef HAVE_SA_HANDLER
# define sa_handler sv_handler
# define sa_mask sv_mask
# define sa_flags sv_flags
#endif
#endif /* HAVE_SIGACTION */

struct bindtable_t
{
  bttype_t type;
  const char *name;
  union {
    binding_t *bind;
    NODE *tree;
  } list;
  binding_t *lr;			/* last resort - for B_UNIQ unly */
  bindtable_t *next;
};

/* ----------------------------------------------------------------------------
 * bindtables functions
 */

static bindtable_t *Tables = NULL;

bindtable_t *Add_Bindtable (const char *name, bttype_t type)
{
  bindtable_t *bt;

  if (Tables == NULL)
    bt = Tables = safe_calloc (1, sizeof(bindtable_t));
  else
  {
    for (bt = Tables; bt; bt = bt->next)
    {
      if (!safe_strcmp (bt->name, name))
	break;
      if (!bt->next)
      {
	bt->next = safe_calloc (1, sizeof(bindtable_t));
	bt = bt->next;
	break;
      }
    }
  }
  if (!bt->name)
    bt->name = safe_strdup (name);
  if (bt->type != B_UNDEF && bt->type != type && type != B_UNDEF)
    Add_Request (I_LOG, "*", F_ERROR,
		 "binds: illegal redefinition of type of bindtable!");
  else if (type != B_UNDEF)
    /* TODO: convert from B_UNDEF to new table type here */
    bt->type = type;
  dprint (1, "binds: added bindtable with name \"%s\"", name);
  return bt;
}

static bindtable_t *Try_Bindtable (const char *name, int force_add)
{
  bindtable_t *bt = Tables;

  for (; bt; bt = bt->next)
    if (!safe_strcmp (bt->name, name))
      break;
  if (bt || !force_add)
    return bt;
  return Add_Bindtable (name, B_UNDEF);	/* default type */
}

binding_t *Add_Binding (const char *table, const char *mask, userflag gf,
		      userflag cf, Function func)
{
  bindtable_t *bt = Try_Bindtable (table, 1);
  binding_t *bind = safe_malloc (sizeof(binding_t));
  binding_t *b;

  if (bt->type == B_UNIQ)
  {
    if (!mask || !*mask)
    {
      bind->key = NULL;
      bind->gl_uf = gf;
      bind->ch_uf = cf;
      bind->name = NULL;
      bind->func = func;
      bind->prev = bt->lr;
      bt->lr = bind;
      dprint (1, "binds: added last resort binding to bindtable \"%s\"", table);
      return bind;
    }
    if (bt->list.tree && (b = Find_Key (bt->list.tree, mask)))
    {
      if (b->func == func && b->gl_uf == gf && b->ch_uf == cf)
      {
	FREE (&bind);				/* duplicate binding */
	return NULL;
      }
      /* now replace data in current leaf with new and insert new */
      memcpy (bind, b, sizeof(binding_t));
      b->prev = bind; /* new previous binding */
      bind = b;
    }
    else
    {
      bind->key = safe_strdup (mask);
      if (Insert_Key (&bt->list.tree, bind->key, bind, 1))
      {
	FREE (&bind->key);			/* tree error */
	FREE (&bind);
	return NULL;
      }
      bind->prev = NULL;
    }
  }
  else /* not B_UNIQ */
  {
    binding_t *last = NULL;

    bind->prev = NULL;				/* if it's really unique */
    for (b = bt->list.bind; b; b = b->next)	/* check if binding is duplicate */
    {
      if (!safe_strcasecmp (b->key, mask))	/* the same mask found! */
      {
	if (b->func == func && b->gl_uf == gf && b->ch_uf == cf)
	{
	  FREE (&bind->key);			/* duplicate binding */
	  FREE (&bind);
	  return NULL;
	}
	if (bt->type == B_UCOMPL || bt->type == B_UNIQMASK)
	{
	  bind->prev = b;
	  b = b->next;
	  break;
	}
      }
      last = b;
    }
    if (bind->prev)
      bind->key = bind->prev->key;
    else
      bind->key = safe_strdup (mask);
    bind->next = b;				/* next after current */
    if (last)
      last->next = bind;			/* insert as last binding */
    else
      bt->list.bind = bind;			/* insert as first binding */
  }
  bind->gl_uf = gf;
  bind->ch_uf = cf;
  bind->name = NULL;
  bind->func = func;
  dprint (1, "binds: added binding to bindtable \"%s\" with mask \"%s\"",
	  table, mask);
  return bind;
}

void Delete_Binding (const char *table, Function func)
{
  bindtable_t *bt = Try_Bindtable (table, 0);
  binding_t *bind, *b, *last = NULL, *next;

  if (bt == NULL)
    return;
  for (b = bt->lr; b; )			/* first pass: ckeck last resort */
  {
    if (b->func == func)
    {
      if (last)
	last->prev = bind = b->prev;
      else
	bt->lr = bind = b->prev;
      dprint (1, "binds: deleting last resort binding from bindtable \"%s\"",
	      table);
      FREE (&b);
      b = bind;
    }
    else
    {
      last = b;
      b = b->prev;
    }
  }
  if (bt->type == B_UNIQ)		/* second pass: check list */
  {
    LEAF *l = NULL;

    while ((l = Next_Leaf (bt->list.tree, l, NULL)))
    {
      for (b = l->s.data; b; )
      {
	if (b->func == func)
	{
	  dprint (1, "binds: deleting binding from bindtable \"%s\" with key \"%s\"",
		  table, b->key);
	  if (last)			/* it's not first binding - remove */
	  {
	    last->prev = bind = b->prev;
	    FREE (&b);
	    b = bind;
	  }
	  else if (b->prev)		/* it's first binding - replace */
	  {
	    bind = b->prev;
	    memcpy (b, bind, sizeof(binding_t));
	    FREE (&bind);
	  }
	  else				/* it's only binding - free leaf */
	  {
	    Delete_Key (bt->list.tree, b->key, b);
	    FREE (&b->key);
	    FREE (&b);
	    b = l->s.data;			/* next leaf is moved here */
	  }
	}
	else
	{
	  last = b;
	  b = b->prev;
	}
      }
    }
  }
  else for (b = bt->list.bind, last = NULL; b; )
  {
    for (bind = b, next = NULL; bind; )	/* try descent into it */
    {
      if (bind->func == func)
      {
	dprint (1, "binds: deleting binding from bindtable \"%s\" with mask \"%s\"",
		table, bind->key);
	if (next)			/* it's not first binding */
	{
	  next->prev = bind->prev;
	  FREE (&bind);
	  bind = next->prev;
	}
	else if (bind->prev)		/* it's first binding */
	{
	  b = bind->prev;
	  FREE (&bind);
	  if (!last)				/* skip current */
	    bt->list.bind = b;
	  else for (bind = last; bind; bind = bind->prev)
	    bind->next = b;
	  bind = b;
	}
	else				/* only binding - delete it */
	{
	  b = bind->next;
	  if (!last)
	    bt->list.bind = b;
	  else
	    last->next = b;
	  FREE (&bind->key);
	  FREE (&bind);
	  bind = b;
	}
      }
      else /* bind->func != func */
      {
	next = bind;
	bind = next->prev;
      }
    } /* all b->prev are checked now */
    last = b;
    if (b)
      b = b->next;
  }
}

binding_t *Check_Bindtable (bindtable_t *bt, const char *str, userflag gf,
			  userflag cf, binding_t *bind)
{
  int i = 0;
  binding_t *b;
  char buff[LONG_STRING];
  register char *ch = buff;
  register const char *s = NONULL(str);
  char cc = ' ';
  size_t sz;

  if (bt == NULL || bt->type == B_UNDEF)
    return NULL;
  if (bt->type == B_MASK || bt->type == B_UNIQMASK)
    cc = 0;
  else if (bt->type == B_MATCHCASE)
  {
    cc = 0;
    i++;
  }
  for (; *s && *s != cc && ch < &buff[sizeof(buff)-1]; ch++, s++)
  {
    if (i)
      *ch = *s;
    else
      *ch = tolower (*s);
  }
  *ch = 0;
  if (bt->type == B_UNIQ)
  {
    b = Find_Key (bt->list.tree, buff);
    if (b && (b->gl_uf & gf) != b->gl_uf && (b->ch_uf & cf) != b->ch_uf)
      b = NULL;
  }
  else
  {
    b = bt->list.bind;
    sz = strlen (buff);
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
	case B_KEYWORD:
	case B_UCOMPL:
	  if (!safe_strcmp (b->key, buff))	/* exact matching */
	    i = 1;
	  else if (bt->type == B_UCOMPL && !safe_strncmp (b->key, buff, sz))
	  {
	    if (bind)
	      i = -1;		/* more than one matched, wait to exact */
	    else
	      bind = b;		/* that is matched to completion */
	  }
	  break;
	case B_MASK:
	case B_UNIQMASK:
	case B_MATCHCASE:
	  i = match (b->key, str) + 1;
	  break;
      }
      if (i > 0)
	break;
    }
  }
  if (bt->type == B_UCOMPL && !i)
    b = bind;			/* completion */
  if (b)
    dprint (2, "binds: bindtable \"%s\" string \"%s\", flags 0x%x/0x%x, found mask \"%s\"",
	    bt->name, str, gf, cf, b->key);
  else if (bt->type == B_UNIQ && bt->lr)
  {
    dprint (2, "binds: bindtable \"%s\" string \"%s\", using last resort",
	    bt->name, str);
    return bt->lr;
  }
  return b;
}

#define __INIT_C 1
/* define functions & variables first */
#include "init.h"

int RunBinding (binding_t *bind, const uchar *uh, char *fst, char *sec, int num,
		char *last)
{
  char uhost[STRING] = "";
  char n[16];
  char *a[6];
  register int i = 0;

  if (!bind || !bind->name || !bind->func)	/* checking... */
    return 0;
  dprint (3, "init:RunBinding: %s %s %s %s %d %s", bind->name,
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

static iftype_t confirm_sig (INTERFACE *iface, ifsig_t sig)
{
  pthread_mutex_lock (&((confirm_t *)iface->data)->mutex);
  ((confirm_t *)iface->data)->res &= 1;		/* reset to FALSE/TRUE */
  pthread_mutex_unlock (&((confirm_t *)iface->data)->mutex);
  return 0;		/* don't kill it, it will be killed by Confirm() */
}

static int confirm_req (INTERFACE *iface, REQUEST *req)
{
  if (req)				/* only requests are accepting */
  {
    pthread_mutex_lock (&((confirm_t *)iface->data)->mutex);
    if (req->string[0] == 'y')				/* yes */
      ((confirm_t *)iface->data)->res = TRUE;
    else if (req->string[0] != 0)			/* no */
      ((confirm_t *)iface->data)->res = FALSE;
    else						/* default */
      ((confirm_t *)iface->data)->res &= 1;
    pthread_mutex_unlock (&((confirm_t *)iface->data)->mutex);
  }
  return REQ_OK;
}

static pthread_mutex_t ConfirmLock = PTHREAD_MUTEX_INITIALIZER;
static unsigned short _confirm_num = 0;

static void confirm_cleanup (void *newif)
{
  register confirm_t *ct = ((INTERFACE *)newif)->data;

  ((INTERFACE *)newif)->data = NULL;		/* it's not allocated! */
  ((INTERFACE *)newif)->ift = I_DIED;
  pthread_mutex_unlock (&ConfirmLock);
  pthread_mutex_destroy (&ct->mutex);
}

bool Confirm (char *message, bool defl)
{
  INTERFACE *newif;
  INTERFACE *ui;
  confirm_t ct;
  char n[8];
  struct timespec tp;

  if (!(defl & ASK))
    return defl;
  ct.res = defl;
  pthread_mutex_lock (&ConfirmLock);		/* don't mix all confirmations */
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
  tp.tv_sec = 0;
  tp.tv_nsec = 50000000L;			/* 0.05s recheck interval */
  pthread_cleanup_push (&confirm_cleanup, newif);
  FOREVER
  {
    pthread_mutex_lock (&ct.mutex);
    if (!(ct.res & ASK))
    {
      pthread_mutex_unlock (&ct.mutex);
      break;
    }
    pthread_mutex_unlock (&ct.mutex);
    nanosleep (&tp, NULL);			/* it may be cancelled here */
  }
  pthread_cleanup_pop (1);
  return ct.res;
}

/* ----------------------------------------------------------------------------
 * config generation
 */

/* config file interface when generating */
static INTERFACE *ConfigFileIface = NULL;
static FILE *ConfigFileFile = NULL;

static int _cfile_req (INTERFACE *iface, REQUEST *req)
{
  if (req && req->string[0])
  {
    if (req->flag & F_REPORT)			/* from console */
      fprintf (ConfigFileFile, "%s\n\n", req->string);
    else					/* from help */
      fprintf (ConfigFileFile, "# %s\n", req->string);
  }
  return REQ_OK;
}

static INTERFACE *Init = NULL;
static char _usage[MESSAGEMAX];

/*
 * Interface I_INIT:
 *   if F_REPORT then bounce to config file
 *   else store it in _usage[] - it was from console
 */
static int _config_req (INTERFACE *iface, REQUEST *req)
{
  register char *c;

  if (req)
  {
    if (req->flag & F_REPORT)
    {
      if (ConfigFileFile)
	return _cfile_req (ConfigFileIface, req);
      return REQ_OK;
    }
    c = req->string;
    while (*c == ' ') c++;			/* ltrim it */
    if (*c)
      strfcpy (_usage, c, sizeof(_usage));
  }
  return REQ_OK;
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
  if (cons && !(cons->ift & I_DIED)) do
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
    } while (!(cons->ift & I_DIED));
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
  if (!Init || !cons || (cons->ift & I_DIED))
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
  } while (!(cons->ift & I_DIED));
  if (!_usage[0] || _usage[0] == '\n')	/* just "Enter" was pressed */
    return 0;
  if (_usage[0] == '?')
    Get_Help ("function", name, cons, -1, -1, NULL, "\n", 2);
  /* start - check if valid */
  else if ((*func) (_usage) != 0 && ConfigFileIface)
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

static bindtable_t *BT_Reg = NULL;
static bindtable_t *BT_Unreg = NULL;
static bindtable_t *BT_Fn = NULL;
static bindtable_t *BT_Unfn = NULL;
static bindtable_t *BT_Script = NULL;

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

static void _lock_var (const char *name)
{
  VarData *data;

  data = Find_Key (VTree, name);
  if (data)
    data->len = 2;				/* set read-only */
}

static int _add_var (const char *name, void *var, size_t s)
{
  VarData *data;

  if (O_GENERATECONF != FALSE && s != 2)	/* not read only */
    Get_ConfigFromConsole (name, var, s);
  if ((data = Find_Key (VTree, name)))		/* already registered */
  {
    if (data->data != var)
      Add_Request (I_LOG, "*", F_WARN,
		   "init: another data already binded to variable \"%s\"", name);
    return 0;
  }
  dprint (3, "init:_add_var: %s %u", name, (unsigned int)s);
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
  binding_t *bind = NULL;

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

int RegisterString (const char *name, char *str, size_t len, int ro)
{
  return _register_var (name, str, ro ? 2 : len);
}

static int _del_var (const char *name)
{
  VarData *data;

  if (!(data = Find_Key (VTree, name)))		/* not registered? */
  {
    Add_Request (I_LOG, "*", F_WARN,
		 "init: attempting delete non-existent variable \"%s\"", name);
    return 0;
  }
  dprint (3, "init:_del_var: %s", name);
  Delete_Key (VTree, name, data);
  FREE (&data);
  return 1;
}

int UnregisterVariable (const char *name)
{
  int i = 0;
  binding_t *bind = NULL;

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

  dprint (3, "init:_add_fn: %s", name);
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
  dprint (3, "init:_del_fn: %s", name);
  Delete_Key (STree, name, data);
  FREE (&data);
  return 1;
}

int
RegisterFunction (const char *name, int (*func)(const char *), const char *msg)
{
  int i;
  binding_t *bind = NULL;

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
  binding_t *bind = NULL;

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
  dprint (3, "init:_add_fl: %s %hd:%hd", name, n0, n1);
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
  return _add_fl (name, 0, 0);			/* disabled per default */
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
    if (cons && !(cons->ift & I_DIED))
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
      } while (!(cons->ift & I_DIED));
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
  dprint (3, "init:_add_fmt: %s", name);
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
  strfcpy (data->f.mt, NONULL(val), FORMATMAX);
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
  int i = 0;

  BindResult = cmd;
  snprintf (cmd, sizeof(cmd), "not permitted to load %s", name);
  if (lstat (name, &st) || !(st.st_mode & S_IRUSR))
    return -1;
  if (!(S_ISREG (st.st_mode)))			/* only regular file! */
    return -1;
  if ((f = fopen (name, "r")))
  {
    if (!Init)
      ask = 0;
    if (ask)					/* find and lock */
      cons = Find_Iface (I_CONSOLE, NULL);
    while (fgets (cmd, sizeof(cmd), f))
    {
      i++;
      c = cmd;
      while (*c == ' ') c++;
      if (*c == '#')				/* comment */
	continue;
      c += strcspn (c, "\n ");
      if (*c)					/* delimit the command */
        *c++ = 0;
      while (*c == ' ') c++;			/* left trim */
      StrTrim (c);				/* right trim */
      if (!*c)					/* empty line */
	continue;
      if (!(data = Find_Key (STree, cmd)))	/* not found! */
      {
	Add_Request (I_LOG, "*", F_BOOT, "%s: line %d: unknown command, ignored",
		     name, i);
	continue;
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
	  if (cons->ift & I_DIED)
	    ask = 0;
	} while (!_usage[0] && ask);
	if (_usage[0] == 'n')			/* "n" entered - abort line */
	  continue;
      }
      if ((data->f.n) (c) == 0)			/* exec command */
      {
	Add_Request (I_LOG, "*", F_BOOT, "%s: line %d: illegal command, ignored",
		     name, i);
	continue;
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
  dprint (3, "init:Config_Exec: %s %s", cmd, args);
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
      NextWord_Unquoted ((char *)data->data, val, data->len);
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
  binding_t *bind;
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
  if ((f = fopen (FormatsFile, "r")))
  {
    while (fgets (fmt, sizeof(fmt), f))
    {
      c = fmt;
      if (*c == '#')				/* comment */
	continue;
      c += strcspn (c, "\n ");
      if (*c)					/* delimit the format name */
        *c++ = 0;
      while (*c == ' ') c++;			/* skip spaces */
      if (!*c)					/* empty line */
	continue;
      if ((data = Find_Key (FTree, fmt)))	/* if format found */
	NextWord_Unquoted (data->f.mt, c, FORMATMAX);
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
  if ((f = fopen (FormatsFile, "w")))
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
 * int func(peer_t *from, char *args)
 */

		/* .set [<variable>[ <value>]] */
static int dc_set (peer_t *dcc, char *args)
{
  char var[STRING];
  VarData *data = NULL;

  StrTrim (args);
  if (args && !*args)
    args = NULL;
  if (args)				/* any variable */
  {
    register char *c;

    for (c = var; *args && *args != ' ' && c < &var[sizeof(var)-1]; )
      *c++ = *args++;
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
	New_Request (dcc->iface, 0, "%s", var);
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
      New_Request (dcc->iface, 0, "%s", var);
  }
  return 1;
}

		/* .fset [<format variable>[ <value>]] */
static int dc_fset (peer_t *dcc, char *args)
{
  char var[STRING];
  VarData2 *data = NULL;

  StrTrim (args);
  if (args && !*args)
    args = NULL;
  if (args)				/* any format */
  {
    register char *c;

    for (c = var; *args && *args != ' ' && c < &var[sizeof(var)-1]; )
      *c++ = *args++;
    *c = 0;
    data = Find_Key (FTree, var);
    if (!data)
      return 0;
    c = NextWord (args);
    if (*c)
      NextWord_Unquoted (data->f.mt, c, FORMATMAX);
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
	New_Request (dcc->iface, 0, "%s", var);
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
      New_Request (dcc->iface, 0, "%s", var);
  }
  return 1;
}

		/* .status [-a|<module name>] */
static int dc_status (peer_t *dcc, char *args)
{
  char ifsig[sizeof(ifsig_t)] = {S_REPORT};
  char buff[STRING];

  if (args && !*args)
    args = NULL;
  else if (args && !strcmp (args, "-a"))
    args = "*";
  printl (buff, sizeof(buff),
_("Universal network client " PACKAGE ", version " VERSION ".\n\
Operating system %s, hostname %@, started %*."),
	  0, NULL, hostname, Nick, NULL, 0L, 0, 0, ctime (&StartTime));
  New_Request (dcc->iface, 0, buff);
  if (!args)
  {
    Status_Interfaces (dcc->iface);
    Status_Sheduler (dcc->iface);
    Status_Clients (dcc->iface);
  }
  else
  {
    ReportFormat = "%*";
    Add_Request (I_MODULE, args, F_SIGNAL, ifsig);
  }
  return 1;
}

		/* .binds [-l|<name>|-a [<name>]] */
static int dc_binds (peer_t *dcc, char *args)
{
  int io;
  bindtable_t *bt;
  binding_t *b = NULL;
  char *c;
  char flags[128];
  LEAF *l = NULL;

  if (args && args[0] == '-')
  {
    if (args[1] == 'l')			/* list of bindtables */
    {
      New_Request (dcc->iface, 0, "Name                Type            Num of bindings");
      for (bt = Tables; bt; bt = bt->next)
      {
	io = 0;
	if (bt->type == B_UNIQ)
	  while ((l = Next_Leaf (bt->list.tree, l, NULL)))
	    io++;
	else
	  for (b = bt->list.bind; b; b = b->next)
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
	  case B_UCOMPL:
	    c = _("try completion ");
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
    if (bt->type == B_UNIQ)
    {
      if ((l = Next_Leaf (bt->list.tree, NULL, NULL)))
	b = l->s.data;
    }
    else
      b = bt->list.bind;
    while (b)
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
      if (bt->type == B_UNIQ)
      {
	if ((l = Next_Leaf (bt->list.tree, l, NULL)))
	  b = l->s.data;
	else
	  b = NULL;
      }
      else
	b = b->next;
    }
  }
  else for (bt = Tables; bt; bt = bt->next)
  {
    if (!bt->list.bind)		/* list.bind has the same size as list.tree */
      continue;
    New_Request (dcc->iface, 0, _("  Bindtable %s:"), bt->name);
    New_Request (dcc->iface, 0, "Key                     Flags   Interpreter     Command");
    if (bt->type == B_UNIQ)
    {
      if ((l = Next_Leaf (bt->list.tree, NULL, NULL)))
	b = l->s.data;
    }
    else
      b = bt->list.bind;
    while (b)
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
      if (bt->type == B_UNIQ)
      {
	if ((l = Next_Leaf (bt->list.tree, l, NULL)))
	  b = l->s.data;
	else
	  b = NULL;
      }
      else
	b = b->next;
    }
  }
  return 1;
}

		/* .module -l */
		/* .module [-c|-d] <module name> */
static int dc_module (peer_t *dcc, char *args)
{
  if (!args || !*args)
    return 0;
  BindResult = _("Success");
  if (Config_Exec ("module", args) == 0)
    BindResult = _("Fail");
  New_Request (dcc->iface, 0, "%s", BindResult);
  return 1;
}

		/* .rehash */
static int dc_rehash (peer_t *dcc, char *args)
{
  char i[sizeof(ifsig_t)] = {S_FLUSH};

  New_Request (dcc->iface, 0, "Rehashing...");
  if (ParseConfig (Config, 0))
    bot_shutdown (BindResult, 3);
  Add_Request (-1, "*", F_SIGNAL, i);    /* flush all interfaces */
  return 1;
}

		/* .restart */
static int dc_restart (peer_t *dcc, char *args)
{
  New_Request (dcc->iface, 0, "Restarting...");
  init();
  return -1;	/* don't log it :) */
}

		/* .die [<reason>] */
static void dc_die (peer_t *dcc, char *args)
{
  char message[MESSAGEMAX];

  if (dcc)
  {
    snprintf (message, sizeof(message), _("Killed by %s%c %s"),
	      dcc->iface->name, (args && *args) ? ':' : '!', NONULL(args));
    bot_shutdown (message, 0);
  }
  else
    bot_shutdown (args, 0);
  exit (0);
}

/* ----------------------------------------------------------------------------
 * helpers for client matching
 */

static bindtable_t *BT_IsOn = NULL;
static bindtable_t *BT_Inspect = NULL;

int Lname_IsOn (const char *pub, const char *lname, const char **name)
{
  binding_t *bind;
  const char *c, *nt;
  clrec_t *netw;

  if (!pub)
    return 0;
  if ((c = strrchr (pub, '@'))) /* network community */
    netw = Lock_Clientrecord (c++);
  else /* my link */
    netw = Lock_Clientrecord ((c = pub));
  if (netw)
  {
    if ((Get_Flags (netw, NULL) & (U_SPECIAL | U_BOT)) &&
	(nt = Get_Field (netw, ".logout", NULL))) /* get network type */
      bind = Check_Bindtable (BT_IsOn, nt, -1, -1, NULL);
    else
      bind = NULL;
    Unlock_Clientrecord (netw);
  }
  else
    bind = NULL;
  if (!bind || bind->name)
    return 0;		/* no such network/service */
  return bind->func (c, pub, lname, name);
}

modeflag Inspect_Client (const char *pub, const char *name, const char **lname,
			 const char **host, time_t *idle)
{
  binding_t *bind;
  const char *c, *nt;
  clrec_t *netw;

  if (!pub)
    return 0;
  if ((c = strrchr (pub, '@'))) /* network community */
    netw = Lock_Clientrecord (c++);
  else /* my link */
    netw = Lock_Clientrecord ((c = pub));
  if (netw)
  {
    if ((Get_Flags (netw, NULL) & (U_SPECIAL | U_BOT)) &&
	(nt = Get_Field (netw, ".logout", NULL))) /* get network type */
      bind = Check_Bindtable (BT_Inspect, nt, -1, -1, NULL);
    else
      bind = NULL;
    Unlock_Clientrecord (netw);
  }
  else
    bind = NULL;
  if (!bind || bind->name)
    return 0;		/* no such network/service */
  return bind->func (c, pub, name, lname, host, idle);
}

/* ----------------------------------------------------------------------------
 * main init()
 */

static void sighup_handler (int signo)
{
  char i[sizeof(ifsig_t)] = {S_FLUSH};

  Add_Request (I_LOG, "*", F_BOOT, "Got SIGHUP: rehashing...");
  Add_Request (-1, "*", F_SIGNAL, i);	/* flush all interfaces */
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

static iftype_t _init_sig (INTERFACE *iface, ifsig_t sig)
{
  if (sig == S_REG)
    _init_all();
  return 0;
}

static void _bind_destroy (void *bind)
{
  binding_t *b = bind;

  if (b)
    FREE (&b->key);
  while (b)
  {
    bind = b->prev;
    FREE (&b);
    b = bind;
  }
}

void init (void)
{
  int g = O_GENERATECONF;
  struct sigaction act;
  char new_path[PATH_MAX+FILENAME_LENGTH+2];
  char *msg;
  char ifsig[sizeof(ifsig_t)] = {S_TERMINATE};
  bindtable_t *bt;
  binding_t *b;

//
// ���� 0 - ������������� �����, ��� ���������������� � core
//
// �������� �������� core:
//  - ������� "listen", "module"
//  - ������� ����������� ����������, ������, ��������
//  - bindtables
//  - ���������� ������� "set", "script"
//  - help "main", "set"
// ������� core � ����������� ��������������:
//  - sheduler
//  - listfile
// ������� core, �� ��������� �������������:
//  - dcc support
//  - wtmp
//  - sockets
//  - main loop
//
  /* kill all modules */
  Add_Request (I_MODULE, "*", F_SIGNAL, ifsig);
  /* I think I need to destroy trees ? */
  Destroy_Tree (&VTree, free);
  Destroy_Tree (&STree, free);
  /* empty all bindtables */
  for (bt = Tables; bt; bt = bt->next)
  {
    if (bt->type == B_UNIQ)
      Destroy_Tree (&bt->list.tree, &_bind_destroy);
    else while (bt->list.bind)
    {
      b = bt->list.bind;
      bt->list.bind = b->next;
      _bind_destroy (b);
    }
  }
  /* init sheduler to have current time */
  IFInit_Sheduler();
  /* add own bindtables and bindings */
  BT_Reg = Add_Bindtable ("register", B_MASK);
  BT_Unreg = Add_Bindtable ("unregister", B_MASK);
  BT_Fn = Add_Bindtable ("function", B_MASK);
  BT_Unfn = Add_Bindtable ("unfunction", B_MASK);
  BT_Script = Add_Bindtable ("script", B_UNIQMASK);
  BT_IsOn = Add_Bindtable ("ison", B_UNIQ);
  BT_Inspect = Add_Bindtable ("inspect-client", B_UNIQ);

  _add_fn ("set", &cfg_set, NULL);		/* add operators */
  _add_fn ("script", &cfg_script, NULL);	/* but don't ask */
  _add_fn ("flood-type", &cfg_flood_type, NULL);
  /* init all */
  if ((msg = IFInit_DCC()))
    bot_shutdown (msg, 3);
  /* load help for variables and more */
  Add_Help ("set");
  Add_Help ("main");
  /* it can be recall of init so don't create another */
  if (!Init)
    Init = Add_Iface (NULL, I_INIT, &_init_sig, &_config_req, NULL);
  Init->ift &= ~I_LOCKED;			/* must be not locked! */
//
// ���� 1 - ������������� ���������� � �������� �������, ���� �� ������ "-r"
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
// ���� 2 - ��������������� � ��������, ���� ������ "-r" ��� "-g"
//          ��������� �������� ���� ����������, � �.�. �� ������� �� �������
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
    ConfigFileIface->ift = I_TEMP;		/* create interface */
  }
  if (g != FALSE || O_DEFAULTCONF != FALSE)
  {
    /* reregister all, ask, and write to config */
    ifsig[0] = S_REG;
    O_GENERATECONF = TRUE;
    Add_Request (-1, "*", F_SIGNAL, ifsig);
    _set_floods ();
    /* ask to include any new scripts */
    while (Start_FunctionFromConsole ("script", &cfg_script, "filename"));
    /* put all "script" calls to new config */
    fprintf (ConfigFileFile, "%s\n", _Scripts_List);
    FREE (&_Scripts_List);
    /* ending */
  }
  _lock_var ("charset");		/* not changeable anymore */
  if ((msg = IFInit_Users()))		/* try to load listfile */
    bot_shutdown (msg, 3);
  if (!_load_formats())			/* try to load formats */
    Add_Request (I_LOG, "*", F_BOOT, "Loaded formats file \"%s\"", FormatsFile);
//
// �������� - ���������� ������ �������, ���� ������ "-g"
//
  if (g != FALSE)
  {
    fclose (ConfigFileFile);			/* save new config, mode 0700 */
    chmod (new_path, S_IRUSR | S_IWUSR | S_IXUSR);
    unlink (Config);				/* delete old config */
    rename (new_path, Config);
    ConfigFileIface->ift |= I_DIED;		/* delete interface */
    ConfigFileFile = NULL;
    ConfigFileIface = NULL;
  }
  /* Init have to get signal S_REG so don't kill it */
  Init->ift |= I_LOCKED;
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