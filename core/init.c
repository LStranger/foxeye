/*
 * Copyright (C) 1999-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is part of FoxEye's source: variables and functions registering
 *   and init; scripts registering and export; config parser; bindtables layer.
 * Bindtables: register unregister function unfunction script
 */

#include "foxeye.h"

#include <signal.h>
#include <ctype.h>
#include <locale.h>
#include <fcntl.h>

#include "direct.h"
#include "tree.h"
#include "list.h"
#include "wtmp.h"

struct bindtable_t
{
  const char *name;
  union {
    struct binding_t *bind;
    NODE *tree;
  } list;
  struct binding_t *lr;			/* last resort - for B_UNIQ unly */
  struct bindtable_t *next;
  bttype_t type;
};

/* ----------------------------------------------------------------------------
 * bindtables functions
 */

static struct bindtable_t *Tables = NULL;

static void _bt_convert2uniqtype (struct bindtable_t *bt, bttype_t type)
{
  struct binding_t *b;
  struct binding_t **last = &bt->list.bind;

  for (; (b = (*last)); last = &(*last)->next)
    while (b->next)
    {
      if (!safe_strcasecmp ((*last)->key, b->next->key))
      {
	b->next->prev = *last;
	*last = b->next;			/* replace head with found */
	b->next = b->next->next;		/* skip found from there */
	(*last)->next = (*last)->prev->next;	/* noop if two consequent */
	FREE (&(*last)->key);			/* replace duplicate key */
	(*last)->key = (*last)->prev->key;
      }
      b = b->next;
    }
  bt->type = type;				/* bindtable is uniqued now */
  if (type != B_UNIQ && type != B_KEYWORD)
    return;
  b = bt->list.bind;
  bt->list.tree = NULL;
  while (b)					/* now create tree */
  {
    if (b->key)
    {
      if (Insert_Key (&bt->list.tree, b->key, b, 1))
      {
	struct binding_t *b2 = b, *b3;

	ERROR ("bindtable conversion error (tree error): \"%s\":\"%s\"",
	       NONULL(bt->name), b->key);
	b = b->next;
	while (b2)
	{
	  b3 = b2->prev;
	  FREE (&b2->key);
	  FREE (&b2);
	  b2 = b3;
	}
	continue;
      } else
	DBG ("init.c:rebind:%p key %s/tree", b, b->key);
    }
    else
    {
      bt->lr = b;
      dprint (2, "bindtable conversion: added last resort binding");
    }
    b = b->next;
  }
}

struct bindtable_t *Add_Bindtable (const char *name, bttype_t type)
{
  struct bindtable_t *bt;

  if (Tables == NULL)
    bt = Tables = safe_calloc (1, sizeof(struct bindtable_t));
  else
  {
    for (bt = Tables; bt; bt = bt->next)
    {
      if (!safe_strcmp (bt->name, name))
	break;
      if (!bt->next)
      {
	bt->next = safe_calloc (1, sizeof(struct bindtable_t));
	bt = bt->next;
	break;
      }
    }
  }
  if (!bt->name)
    bt->name = safe_strdup (name);
  if (bt->type != B_UNDEF && bt->type != type && type != B_UNDEF)
    ERROR ("binds: illegal redefinition of type of bindtable!");
  else if (bt->type == B_UNDEF && type != B_UNDEF) switch (type)
  {				/* convert from B_UNDEF to new table type */
    case B_KEYWORD:
    case B_UNIQ:
    case B_UCOMPL:
    case B_UNIQMASK:
      _bt_convert2uniqtype (bt, type);
      break;
    default:
      bt->type = type;
  }
  dprint (2, "binds: added bindtable with name \"%s\"", NONULL(name));
  return bt;
}

static struct bindtable_t *Try_Bindtable (const char *name, int force_add)
{
  struct bindtable_t *bt = Tables;

  for (; bt; bt = bt->next)
    if (!safe_strcmp (bt->name, name))
      break;
  if (bt || !force_add)
    return bt;
  return Add_Bindtable (name, B_UNDEF);	/* default type */
}

struct binding_t *Add_Binding (const char *table, const char *mask, userflag gf,
			       userflag cf, Function func, const char *name)
{
  struct bindtable_t *bt = Try_Bindtable (table, 1);
  struct binding_t *bind = safe_malloc (sizeof(struct binding_t));
  struct binding_t *b;

  if (bt->type == B_UNIQ || bt->type == B_KEYWORD)
  {
    if (!mask || !*mask)
    {
      bind->key = NULL;
      bind->gl_uf = gf;
      bind->ch_uf = cf;
      bind->name = safe_strdup (name);
      bind->func = func;
      bind->prev = bt->lr;
      bind->hits = 0;
      bt->lr = bind;
      dprint (2, "binds: added last resort binding to bindtable \"%s\"%s%s",
	      NONULL(table), name ? " for interpreter function " : "",
	      NONULL(name));
      return bind;
    }
    if (bt->list.tree && (b = Find_Key (bt->list.tree, mask)))
    {
      if (b->func == func && b->gl_uf == gf && b->ch_uf == cf &&
	  !safe_strcmp (b->name, name))
      {
	FREE (&bind);				/* duplicate binding */
	return NULL;
      }
      /* now replace data in current leaf with new and insert new */
      memcpy (bind, b, sizeof(struct binding_t));
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
	ERROR ("init.c:Add_Binding: tree error.");
	return NULL;
      }
      bind->prev = NULL;
    }
    DBG ("init.c:+bind:%p shifted %p/tree", bind, bind->prev);
  }
  else /* not B_UNIQ */
  {
    struct binding_t *last = NULL;

    bind->prev = NULL;				/* if it's really unique */
    for (b = bt->list.bind; b; b = b->next)	/* check if binding is duplicate */
    {
      if (!safe_strcasecmp (b->key, mask))	/* the same mask found! */
      {
	if (b->func == func && b->gl_uf == gf && b->ch_uf == cf &&
	    !safe_strcmp (b->name, name))
	{
	  FREE (&bind);				/* duplicate binding */
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
    DBG ("init.c:+bind:%p shifted %p nextto %p", bind, bind->prev, last);
  }
  bind->gl_uf = gf;
  bind->ch_uf = cf;
  bind->name = safe_strdup (name);
  bind->func = func;
  bind->hits = 0;
  dprint (2, "binds: added binding to bindtable \"%s\" with mask \"%s\"%s%s",
	  NONULL(table), NONULL(mask),
	  name ? " for interpreter function " : "", NONULL(name));
  return bind;
}

void Delete_Binding (const char *table, Function func, const char *name)
{
  struct bindtable_t *bt = Try_Bindtable (table, 0);
  struct binding_t *bind, *b, *last = NULL, *next;

  if (bt == NULL)
    return;
  for (b = bt->lr; b; )			/* first pass: ckeck last resort */
  {
    if (b->func == func && (!name || !safe_strcmp (b->name, name)))
    {
      if (last)
	last->prev = bind = b->prev;
      else
	bt->lr = bind = b->prev;
      dprint (2, "binds: deleting last resort binding from bindtable \"%s\"",
	      NONULL(table));
      FREE (&b->name);
      FREE (&b);
      b = bind;
    }
    else
    {
      last = b;
      b = b->prev;
    }
  }
  if (bt->type == B_UNIQ || bt->type == B_KEYWORD) /* second pass: check list */
  {
    LEAF *l = NULL;

    while ((l = Next_Leaf (bt->list.tree, l, NULL)))
    {
      last = NULL;
      for (b = l->s.data; b; )
      {
	if (b->func == func && (!name || !safe_strcmp (b->name, name)))
	{
	  dprint (2, "binds: deleting binding from bindtable \"%s\" with key \"%s\"",
		  NONULL(table), NONULL(b->key));
	  DBG ("init.c:-bind:%p unshifting %p after %p/tree", b, b->prev, last);
	  if (last)			/* it's not first binding - remove */
	  {
	    last->prev = bind = b->prev;
	    FREE (&b->name);
	    FREE (&b);
	    b = bind;
	  }
	  else if (b->prev)		/* it's first binding - replace */
	  {
	    bind = b->prev;
	    FREE (&b->name);
	    memcpy (b, bind, sizeof(struct binding_t));
	    FREE (&bind);
	  }
	  else				/* it's only binding - free leaf */
	  {
	    Delete_Key (bt->list.tree, b->key, b);
	    FREE (&b->key);
	    FREE (&b->name);
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
  else for (b = bt->list.bind, last = NULL; (bind = b); )
  {
    next = NULL;
    do					/* try descent into it */
    {
      if (bind->func == func && (!name || !safe_strcmp (b->name, name)))
      {
	dprint (2, "binds: deleting binding from bindtable \"%s\" with mask \"%s\"",
		NONULL(table), NONULL(bind->key));
	DBG ("init.c:-bind:%p unshifting %p after %p nextto %p",
		bind, bind->prev, next, last);
	if (next)			/* it's not first binding */
	{
	  next->prev = bind->prev;
	  FREE (&bind->name);
	  FREE (&bind);
	  bind = next->prev;
	}
	else if (bind->prev)		/* it's first binding */
	{
	  b = bind->prev;
	  FREE (&bind->name);
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
	  FREE (&bind->name);
	  FREE (&bind);
	  bind = b;
	}
      }
      else /* bind->func != func */
      {
	next = bind;
	bind = next->prev;
      }
    } while (bind); /* all b->prev are checked now */
    last = b;
    if (b)
      b = b->next;
  }
}

struct binding_t *Check_Bindtable (struct bindtable_t *bt, const char *str,
				   userflag gf, userflag scf,
				   struct binding_t *bind)
{
  int i = 0;
  struct binding_t *b;
  char buff[LONG_STRING];
  register char *ch = buff;
  register userflag tgf, tcf;
  userflag cf;
  register const unsigned char *s = NONULL(str);
  char cc = ' ';
  size_t sz;

  if (bt == NULL || bt->type == B_UNDEF)
    return NULL;
  if (!str &&
      (bt->type == B_UNIQ || bt->type == B_KEYWORD)) { /* scan requested */
    register LEAF *l;

    if (bind) {
      l = Find_Leaf (bt->list.tree, bind->key, 1);
      l = Next_Leaf (bt->list.tree, l, NULL);
    } else
      l = Find_Leaf (bt->list.tree, "", 0);
    return (l == NULL) ? NULL : l->s.data;
  }
  cf = (scf & ~U_EQUAL);		/* drop the flag to matching */
  if (bt->type == B_MASK || bt->type == B_UNIQMASK)
    cc = 0;
  else if (bt->type == B_MATCHCASE)
    i++;
  if (bt->type != B_KEYWORD || !bind)	/* if requested next, skip key check */
  for (; *s && *s != cc && ch < &buff[sizeof(buff)-MB_CUR_MAX]; ch++, s++)
  {
    if (i > 0) /* case insensitive */
      *ch = *s;
    else if (*s < 0x80 || MB_CUR_MAX == 1) /* ascii char */
      *ch = tolower (*s);
    else	/* multibyte encoding */
    {
      wchar_t wc;
      register int sz = mbtowc (&wc, s, MB_LEN_MAX);
      if (sz < 1) /* invalid char */
        *ch = *s;
      else
      {
	s += (sz - 1);
	wc = towlower (wc);
	sz = wctomb (ch, wc);
	ch += (sz - 1);
      }
    }
  }
  *ch = 0;
//  DBG ("init.c:Check_Bindtable:checking for \"%s\":0x%08x/0x%08x", buff, (int)gf, (int)cf);
  if (bt->type == B_UNIQ)
  {
    if (bind)		/* check for invalid call */
    {
      dprint (3, "binds: bindtable \"%s\" duplicate call", NONULL(bt->name));
      return NULL;
    }
    b = Find_Key (bt->list.tree, buff);
    if (scf & U_EQUAL)
    {
      if (b && (gf != b->gl_uf || cf != b->ch_uf))
	b = NULL;
    }
    else if (b)
    {
      if (b->gl_uf & U_NEGATE)				/* -a */
	tgf = (b->gl_uf & ~gf);
      else						/* a */
	tgf = (b->gl_uf & gf);
      if (b->ch_uf & U_NEGATE)				/* -b */
	tcf = (b->ch_uf & ~cf);
      else						/* b */
	tcf = (b->ch_uf & cf);
      if (b->ch_uf & U_AND)
      {
	if (tgf != b->gl_uf || tcf != b->ch_uf)		/* [-]a&[-]b */
	  b = NULL;
      }
      else if (tgf != b->gl_uf && tcf != b->ch_uf)	/* [-]a|[-]b */
	b = NULL;
    }
  }
  else if (bt->type == B_KEYWORD)
  {
    if (!bind)				/* it is first call so find it */
      b = Find_Key (bt->list.tree, buff);
    else				/* else go right to next */
      b = bind->prev;
    if (scf & U_EQUAL)
    {
      while (b && (gf != b->gl_uf || cf != b->ch_uf))
	b = b->prev;			/* skip this one */
    }
    else while (b)
    {
      if (b->gl_uf & U_NEGATE)				/* -a */
	tgf = (b->gl_uf & ~gf);
      else						/* a */
	tgf = (b->gl_uf & gf);
      if (b->ch_uf & U_NEGATE)				/* -b */
	tcf = (b->ch_uf & ~cf);
      else						/* b */
	tcf = (b->ch_uf & cf);
      if (b->ch_uf & U_AND)
      {
	if (tgf == b->gl_uf && tcf == b->ch_uf)		/* [-]a&[-]b */
	  break;			/* found matching */
	b = b->prev;			/* else skip this one */
      }
      else if (tgf == b->gl_uf || tcf == b->ch_uf)	/* [-]a|[-]b */
	break;				/* found matching */
      b = b->prev;			/* else skip this one */
    }
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
      if (scf & U_EQUAL)		/* check exact matching */
      {
	if (gf != b->gl_uf || cf != b->ch_uf || safe_strcmp (b->key, buff))
	  continue;
	i = 1;				/* support for U_COMPL type */
	break;				/* found! */
      }
      if (b->gl_uf & U_NEGATE)				/* -a */
	tgf = (b->gl_uf & ~gf);
      else						/* a */
	tgf = (b->gl_uf & gf);
      if (b->ch_uf & U_NEGATE)				/* -b */
	tcf = (b->ch_uf & ~cf);
      else						/* b */
	tcf = (b->ch_uf & cf);
      if (b->ch_uf & U_AND)
      {
	if (tgf != b->gl_uf || tcf != b->ch_uf)		/* [-]a&[-]b */
	  continue;
      }
      else if (tgf != b->gl_uf && tcf != b->ch_uf)	/* [-]a|[-]b */
	continue;
      switch (bt->type)
      {
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
	  i = match (b->key, buff) + 1;
	  break;
	case B_UNDEF: case B_UNIQ: case B_KEYWORD: ;
	/* never reached but make compiler happy */
      }
      if (i > 0)
	break;
    }
  }
  if (bt->type == B_UCOMPL && !i)
    b = bind;			/* completion */
  if (b)
  {
    dprint (3, "binds: bindtable \"%s\" string \"%s\", flags %#x/%#x, found mask \"%s\"",
	    NONULL(bt->name), NONULL(str), gf, cf, NONULL(b->key));
    b->hits++;
  }
  else if (bt->type == B_UNIQ && bt->lr)
  {
    dprint (3, "binds: bindtable \"%s\" string \"%s\", using last resort",
	    NONULL(bt->name), NONULL(str));
    bt->lr->hits++;
    return bt->lr;
  }
  return b;
}

const char *Bindtable_Name (struct bindtable_t *bt)
{
  if (!bt)
    return NULL;
  return bt->name;
}

#define __INIT_C 1
/* define functions & variables first */
#include "init.h"

int RunBinding (struct binding_t *bind, const uchar *uh, const char *fst,
		const char *sec, char *third, int num, const char *last)
{
  char *tt0;
  char uhost[STRING] = "";
  char n[16];
  const char *a[8];
  register int i = 0;

  if (!bind || !bind->name || !bind->func)	/* checking... */
    return 0;
  dprint (4, "init:RunBinding: %s\t%s\t%s\t%s\t%s\t%d\t%s", bind->name,
	  NONULL((char *)uh), NONULL(fst), NONULL(sec), NONULL(third), num,
	  last ? last : "(nil)");
  BindResult = NULL;				/* clear result */
  if (uh)
  {
    strfcpy (uhost, (char *)uh, sizeof(uhost));	/* nick!user@host -> */
    a[0] = uhost;				/* -> nick user@host */
    if ((a[1] = safe_strchr (uhost, '!')))
      *(((char **)a)[1]++) = 0;
    else
      a[1] = "*";
    i = 2;
  }
  if (fst && *fst)				/* NONULL */
    a[i++] = fst;
  if (sec && *sec)				/* NONULL */
    a[i++] = sec;
  if (third)
  {
    char *tt2 = gettoken (third, &tt0);
    a[i++] = third;
    if (*tt2)					/* third is "X Y" */
      a[i++] = tt2;
    else					/* third is one word */
      tt0 = NULL;
  }
  else
    tt0 = NULL;
  if (num >= 0)					/* below 0 are ignored */
  {
    snprintf (n, sizeof(n), "%d", num);
    a[i++] = n;
  }
  if (last/* && *last*/)				/* NONULL */
    a[i++] = last;
  i = bind->func (bind->name, i, a);		/* int func(char *,int,char **) */
  if (i)					/* return 0 or 1 only */
    i = 1;
  if (tt0)
    *tt0 = ' ';					/* restore third */
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
  char buf[MB_LEN_MAX+1];

  if (req)				/* only requests are accepting */
  {
    pthread_mutex_lock (&((confirm_t *)iface->data)->mutex);
    unistrlower (buf, req->string, sizeof(buf));
    buf[unistrcut (buf, sizeof(buf), 1)] = 0;
    if (buf[0] == 'y' || !strcmp (buf, _("y")))		/* yes */
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

  ((INTERFACE *)newif)->ift = I_DIED;
  pthread_mutex_unlock (&ConfirmLock);
  pthread_mutex_destroy (&ct->mutex);
}

bool Confirm (char *message, bool defl)
{
  INTERFACE *newif;
  INTERFACE *ui;
  confirm_t *ct;
  char n[8];
  struct timespec tp;

  if (!(defl & ASK))
    return defl;
  pthread_mutex_lock (&ConfirmLock);		/* don't mix all confirmations */
  if ((ui = Find_Iface (I_MODULE, "ui")) == NULL)
  {
    pthread_mutex_unlock (&ConfirmLock);
    return (defl & 1);				/* reset to FALSE/TRUE */
  }
  ct = safe_malloc(sizeof(confirm_t));
  ct->res = defl;
  pthread_mutex_init (&ct->mutex, NULL);
  snprintf (n, sizeof(n), "=%hu", _confirm_num);
  _confirm_num++;
  newif = Add_Iface (I_TEMP, n, &confirm_sig, &confirm_req, ct);
  Set_Iface (newif);
  New_Request (ui, F_ASK | F_ASK_BOOL, _("%s (y/n)?[%s] "), message,
	      (defl & 1) == TRUE ? _("y") : _("n"));
  Unset_Iface();	/* newif */
  Unset_Iface();	/* ui */
  tp.tv_sec = 0;
  tp.tv_nsec = 50000000L;			/* 0.05s recheck interval */
  pthread_cleanup_push (&confirm_cleanup, newif);
  FOREVER
  {
    register bool res;

    pthread_mutex_lock (&ct->mutex);
    res = ct->res;
    pthread_mutex_unlock (&ct->mutex);
    if (!(res & ASK))
      break;
    nanosleep (&tp, NULL);			/* it may be cancelled here */
    pthread_testcancel();			/* or here - on non-POSIX */
  }
  pthread_cleanup_pop (1);
  return ct->res;
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

static void _add_var_to_config (const char *name, void *ptr, size_t s, int changed)
{
  char *prefix = changed ? "" : "#";
  if (Init)
  {
    Set_Iface (Init);			/* flush everything now */
    while (Get_Request());
    Unset_Iface();
  }
  Get_Help ("set", name, ConfigFileIface, -1, -1, NULL, NULL, 1);
  if (s > 1)
    New_Request (ConfigFileIface, F_REPORT, "%sset %s %s", prefix, name,
		 _quote_expand ((char *)ptr));
  else if (!s)
    New_Request (ConfigFileIface, F_REPORT, "%sset %s %ld", prefix, name,
		 *(long int *)ptr);
  else if ((*(bool *)ptr & 1) == TRUE)
    New_Request (ConfigFileIface, F_REPORT, "%sset %s %son", prefix, name,
		 (*(bool *)ptr & ASK) ? "ask-" : "");
  else
    New_Request (ConfigFileIface, F_REPORT, "%sset %s %soff", prefix, name,
		 (*(bool *)ptr & ASK) ? "ask-" : "");
  Set_Iface (ConfigFileIface);
  while (Get_Request());		/* write file */
  Unset_Iface();
}

static int Get_ConfigFromConsole (const char *name, void *ptr, size_t s)
{
  INTERFACE *cons = Find_Iface (I_CONSOLE, NULL);
  int prompt = 1, changed = 0;

  if (!cons)
    return 0;
  Unset_Iface();	/* unlock after Find_Iface() */
  if (!Init)
    return 0;
  if (!(cons->ift & I_DIED)) do
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
					(*(bool *)ptr & 1) ? "yes" : "no");
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
	Get_Help ("set", name, cons, -1, -1, NULL, NULL, 2);
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
	  changed = 1;
	}
	break;
      }
    } while (!(cons->ift & I_DIED));
    return changed;
}

static int Start_FunctionFromConsole
		(const char *name, int (*func)(const char *), const char *msg)
{
  INTERFACE *cons = Find_Iface (I_CONSOLE, NULL);

  if (!cons)
    return 0;
  Unset_Iface();
  if (!Init || (cons->ift & I_DIED))
    return 0;
  /* get function parameters */
  Set_Iface (Init);
  New_Request (cons, 0, "add %s? (%s) []: ", name, msg);
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
  if (!_usage[0] || _usage[0] == '\n' )	/* just "Enter" was pressed */
    return 0;
  DBG ("Start_FunctionFromConsole:function %s:got %s", name, _usage);
  if (_usage[0] == '?')
    Get_Help ("function", name, cons, -1, -1, NULL, NULL, 2);
  /* start - check if valid */
  else
    (*func) (_usage);
  return 1;
}

/* ----------------------------------------------------------------------------
 * internal core tables: variables, operators(functions), formats, flood types
 */

static struct bindtable_t *BT_Reg = NULL;
static struct bindtable_t *BT_Unreg = NULL;
static struct bindtable_t *BT_Fn = NULL;
static struct bindtable_t *BT_Unfn = NULL;
static struct bindtable_t *BT_Script = NULL;

static NODE *VTree = NULL;		/* variables */
static NODE *STree = NULL;		/* operators */
static NODE *FTree = NULL;		/* formats */
static NODE *TTree = NULL;		/* flood types */

typedef struct
{
  void *data;
  size_t len;		/* 0 - int, 1 - bool, 2 - constant, >2 - string */
  bool changed;
  char name[1];
} __attribute__ ((packed)) VarData;

static void _lock_var (const char *name)
{
  VarData *data;
  struct binding_t *bind = NULL;

  if (!(data = Find_Key (VTree, name)))
    return;
  data->len = 2;				/* set read-only */
  while ((bind = Check_Bindtable (BT_Reg, "*", U_ALL, U_ANYCH, bind)))
    if (!bind->name)				/* internal only */
      bind->func (name, data->data, 2);		/* call bindings */
}

static inline void _unsharp_var (const char *name)
{
  register VarData *data;

  if (!(data = Find_Key (VTree, name)))
    return;
  data->changed = TRUE;
}

static int _add_var (const char *name, void *var, size_t *s)
{
  VarData *data;
  int i = 0;

  if (O_GENERATECONF != FALSE && *s != 2)	/* if not read-only */
    i = Get_ConfigFromConsole (name, var, *s);
  data = Find_Key (VTree, name);
  if (data && data->changed)
    i = 1;
  if (ConfigFileFile && *s != 2)
    _add_var_to_config (name, var, *s, i);
  if (data)					/* already registered */
  {
    if (data->data != var)
      WARNING ("init: another data is already bound to variable \"%s\"", name);
    else
    {
      dprint (4, "init:_add_var: retry on %s", name);
      if (i) data->changed = TRUE;
      *s = data->len;				/* a little trick for locked */
    }
    return 0;
  }
  dprint (2, "init:_add_var: %s %u", name, (unsigned int)*s);
  data = calloc (1, sizeof(VarData) + safe_strlen(name));
  data->data = var;
  strcpy (data->name, name);
  data->len = *s;
  if (i) data->changed = TRUE;
  if (!Insert_Key (&VTree, data->name, data, 1))	/* try unique name */
    return 1;
  free (data);
  ERROR ("init:_add_var: tree error");
  return 0;
}

static int _register_var (const char *name, void *var, size_t s)
{
  int i;
  struct binding_t *bind = NULL;

  if (!name || !var)
    return 0;
  i = _add_var (name, var, &s);			/* static binding ;) */
  while ((bind = Check_Bindtable (BT_Reg, "*", U_ALL, U_ANYCH, bind)))
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
    WARNING ("init: attempting to delete non-existent variable \"%s\"",
	     NONULL(name));
    return 0;
  }
  dprint (2, "init:_del_var: %s", name);
  Delete_Key (VTree, name, data);
  free (data);
  return 1;
}

int UnregisterVariable (const char *name)
{
  int i = 0;
  struct binding_t *bind = NULL;

  i = _del_var (name);				/* static binding ;) */
  while ((bind = Check_Bindtable (BT_Unreg, "*", U_ALL, U_ANYCH, bind)))
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
  char name[1];
} __attribute__ ((packed)) VarData2;

static int
_add_fn (const char *name, int (*func)(const char *), const char *msg)
{
  int i;
  VarData2 *data;

  dprint (2, "init:_add_fn: %s", NONULL(name));
  if (O_GENERATECONF != FALSE && msg)		/* ask for list */
    do {
      i = Start_FunctionFromConsole (name, func, msg);
    } while (i);
  if ((data = Find_Key (STree, name)))		/* already registered */
  {
    if (data->f.n != func)
      WARNING ("init: another ptr already bound to function \"%s\"", name);
    else
      dprint (4, "init:_add_fn: retry on %s", name);
    return 0;
  }
  data = calloc (1, sizeof(VarData2) + safe_strlen(name));
  data->f.n = func;
  strcpy (data->name, name);
  if (!Insert_Key (&STree, data->name, data, 1))	/* try unique */
    return 1;
  free (data);
  ERROR ("init:_add_fn: tree error");
  return 0;
}

static int _del_fn (const char *name)
{
  VarData2 *data;

  if (!(data = Find_Key (STree, name)))		/* not registered? */
  {
    WARNING ("init: attempting to delete non-existent function \"%s\"",
	     NONULL(name));
    return 0;
  }
  dprint (2, "init:_del_fn: %s", name);
  Delete_Key (STree, name, data);
  free (data);
  return 1;
}

int
RegisterFunction (const char *name, int (*func)(const char *), const char *msg)
{
  int i;
  struct binding_t *bind = NULL;

  if (!name || !func)
    return 0;
  i = _add_fn (name, func, msg);		/* static binding ;) */
  while ((bind = Check_Bindtable (BT_Fn, "*", U_ALL, U_ANYCH, bind)))
    if (!bind->name)				/* internal only */
      i |= bind->func (name, func);
  return i;
}

int UnregisterFunction (const char *name)
{
  int i;
  struct binding_t *bind = NULL;

  i = _del_fn (name);				/* static binding ;) */
  while ((bind = Check_Bindtable (BT_Unfn, "*", U_ALL, U_ANYCH, bind)))
    if (!bind->name)				/* internal only */
      i |= bind->func (name);
  return i;
}

static short *_add_fl (const char *name, short n0, short n1)
{
  VarData2 *data = Find_Key (TTree, name);

  if (data)					/* already registered */
    return data->f.ld;
  dprint (2, "init:_add_fl: %s %hd:%hd", name, n0, n1);
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
  const char *name, *c;
  INTERFACE *cons = Find_Iface (I_CONSOLE, NULL);

  if (!cons)
    return;
  Unset_Iface();
  if (Init && !(cons->ift & I_DIED))
    while ((leaf = Next_Leaf (TTree, leaf, &name)))
    {
      data = leaf->s.data;
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
}

static void _report_floods (void)
{
  LEAF *leaf = NULL;
  VarData2 *data;
  const char *name;

  while ((leaf = Next_Leaf (TTree, leaf, &name)))
  {
    data = leaf->s.data;
    New_Request (ConfigFileIface, F_REPORT, "flood-type %s %hd:%hd", name,
		 data->f.ld[0], data->f.ld[1]);
  }
}

static void _add_fmt (const char *name, char *fmt)
{
  VarData2 *data;

  if (Find_Key (FTree, name))			/* already registered */
    return;
  dprint (2, "init:_add_fmt: %s", name);
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
  if (!args)
    args = "";
  dprint (4, "init:Config_Exec: %s %s", cmd, args);
  return data->f.n (args);
}

static int _set (VarData *data, register const char *val)
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
      NextWord_Unquoted ((char *)data->data, (char *)val, data->len);
  }
  data->changed = TRUE;
  return 1;
}

static ScriptFunction (cfg_set)		/* to config - by registering */
{
  char var[SHORT_STRING];
  VarData *data = NULL;
  register char *c;

  if (args && *args)
  {
    /* any variable */
    for (c = var; *args && *args != ' ' && c < &var[sizeof(var)-1]; )
      *c++ = *args++;
    *c = 0;
    data = Find_Key (VTree, var);
    if (!data)
      return 0;
    return _set (data, NextWord ((char *)args)); /* it's still const */
  }
  return 0;
}

static char *_Scripts_List = NULL;

static ScriptFunction (cfg_script)	/* to config - keep and store */
{
  struct binding_t *bind;
  register size_t ss;

  if (!args || !*args)
    return 0;
  bind = Check_Bindtable (BT_Script, args, U_ALL, U_ANYCH, NULL);
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
    c = NextWord ((char *)args);	/* it's still const */
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
  const char *name;
  FILE *f;

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
 * int func(struct peer_t *from, char *args)
 */

		/* .set [<variable>[ <value>]] */
BINDING_TYPE_dcc (dc_set);
static int dc_set (struct peer_t *dcc, char *args)
{
  char var[STRING];
  VarData *data = NULL;

  if (args && Have_Wildcard (args) < 0)	/* any variable */
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
    const char *name;
    LEAF *leaf = NULL;
    register size_t s, t = 0;

    New_Request (dcc->iface, 0, _("List of variables%s%s:"),
		 args ? _(" by mask ") : "", NONULL(args));
    while ((leaf = Next_Leaf (VTree, leaf, &name)))
    {
      if (args && match (args, name) <= 0)
	continue;
      s = safe_strlen (name) + 16 - t%16;
      if (s + t > 72 && t)
      {
	New_Request (dcc->iface, 0, "%s", var);
	t = strfcpy (var, name, sizeof(var));
      }
      else
      {
	if (t) do {
	  var[t++] = ' ';
	} while (t % 16);
	t += strfcpy (&var[t], name, sizeof(var) - t);
      }
    }
    if (t)
      New_Request (dcc->iface, 0, "%s", var);
  }
  return 1;
}

		/* .fset [<format variable>[ <value>]] */
BINDING_TYPE_dcc (dc_fset);
static int dc_fset (struct peer_t *dcc, char *args)
{
  char var[STRING];
  VarData2 *data = NULL;
  const char *p;
  register int s;


  if (args)
  {
    p = strchr (args, ' ');
    s = Have_Wildcard (args);
    if (s < 0 || (p && &args[s] > p))	/* any format */
    {
      if (p)
	s = p - args;
      else
	s = strlen (args);
      if (s >= (int)sizeof(var))
	s = sizeof(var) - 1;
      strfcpy (var, args, s+1);
      data = Find_Key (FTree, var);
      if (!data)
	return 0;
      p = NextWord (args);
      if (*p)
	NextWord_Unquoted (data->f.mt, (char *)p, FORMATMAX);
      New_Request (dcc->iface, 0, _("Current format %s: %s"), var, data->f.mt);
      return 1;
    }
  }
  {					/* else list of formats */
    LEAF *leaf = NULL;
    register size_t t = 0;

    New_Request (dcc->iface, 0, _("List of formats%s%s:"),
		 args ? _(" by mask ") : "", NONULL(args));
    while ((leaf = Next_Leaf (FTree, leaf, &p)))
    {
      if (args && match (args, p) <= 0)
	continue;
      s = safe_strlen (p) + 16 - t%16;
      if (s + t > 72 && t)
      {
	New_Request (dcc->iface, 0, "%s", var);
	t = strfcpy (var, p, sizeof(var));
      }
      else
      {
	if (t) do {
	  var[t++] = ' ';
	} while (t % 16);
	t += strfcpy (&var[t], p, sizeof(var) - t);
      }
    }
    if (t)
      New_Request (dcc->iface, 0, "%s", var);
  }
  return 1;
}

		/* .status [-a|<module name>] */
BINDING_TYPE_dcc (dc_status);
static int dc_status (struct peer_t *dcc, char *args)
{
  char buff[STRING];

  if (args && !strcmp (args, "-a"))
    args = "*";
  printl (buff, sizeof(buff),
_("Universal network client " PACKAGE ", version " VERSION ".\r\n\
Started %* on %s at host %@."),
	  0, NULL, hostname, Nick, NULL, 0L, 0, 0, ctime (&StartTime));
  New_Request (dcc->iface, 0, "%s", buff);
  if (!args)
  {
    Status_Interfaces (dcc->iface);
    Status_Sheduler (dcc->iface);
    Status_Clients (dcc->iface);
#ifdef HAVE_ICONV
    Status_Encodings (dcc->iface);
#endif
    Status_Connchains (dcc->iface);
    ReportFormat = "%L @%@: %*";
    Send_Signal (I_LISTEN, "*", S_REPORT);
  }
  else
  {
    ReportFormat = "%*";
    Send_Signal (I_MODULE, args, S_REPORT);
  }
  return 1;
}

		/* .binds [-l|<name>|-a [<name>]] */
BINDING_TYPE_dcc (dc_binds);
static int dc_binds (struct peer_t *dcc, char *args)
{
  int io;
  struct bindtable_t *bt;
  struct binding_t *b = NULL;
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
		     NONULLP(bt->name), c, io);
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
    if (bt->type == B_UNIQ || bt->type == B_KEYWORD)
    {
      if ((l = Next_Leaf (bt->list.tree, NULL, NULL)))
	b = l->s.data;
    }
    else
      b = bt->list.bind;
    while (b)
    {
      if (io == 0 || !b->name)
      {
	userflagtostr (b->gl_uf, flags);
	if (b->ch_uf && !(b->ch_uf & U_ANY)) /* if this is set then denied */
	{
	  if (b->ch_uf & U_AND)
	    strfcat (flags, "&", sizeof(flags));
	  else
	    strfcat (flags, "|", sizeof(flags));
	  userflagtostr (b->ch_uf, &flags[strlen(flags)]);
	}
	if (b->name && b->func && b->func ("-", 0, NULL))
	  New_Request (dcc->iface, 0, "%-23.23s %-7.7s %-15.15s %s",
		       NONULLP(b->key), flags, BindResult, b->name);
	else
	  New_Request (dcc->iface, 0, "%-23.23s %s", NONULLP(b->key), flags);
      }
      if (bt->type == B_KEYWORD && b->prev)
	b = b->prev;
      else if (bt->type == B_UNIQ || bt->type == B_KEYWORD)
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
    New_Request (dcc->iface, 0, _("  Bindtable %s:"), NONULLP(bt->name));
    New_Request (dcc->iface, 0, "Key                     Flags   Interpreter     Command");
    if (bt->type == B_UNIQ || bt->type == B_KEYWORD)
    {
      if ((l = Next_Leaf (bt->list.tree, NULL, NULL)))
	b = l->s.data;
    }
    else
      b = bt->list.bind;
    while (b)
    {
      if (io == 0 || !b->name)
      {
	userflagtostr (b->gl_uf, flags);
	if (b->ch_uf && !(b->ch_uf & U_ANY)) /* if this is set then denied */
	{
	  if (b->ch_uf & U_AND)
	    strfcat (flags, "&", sizeof(flags));
	  else
	    strfcat (flags, "|", sizeof(flags));
	  userflagtostr (b->ch_uf, &flags[strlen(flags)]);
	}
	if (b->name && b->func && b->func ("-", 0, NULL))
	  New_Request (dcc->iface, 0, "%-23.23s %-7.7s %-15.15s %s",
		       NONULLP(b->key), flags, BindResult, b->name);
	else
	  New_Request (dcc->iface, 0, "%-23.23s %s", NONULLP(b->key), flags);
      }
      if (bt->type == B_KEYWORD && b->prev)
	b = b->prev;
      else if (bt->type == B_UNIQ || bt->type == B_KEYWORD)
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
BINDING_TYPE_dcc (dc_module);
static int dc_module (struct peer_t *dcc, char *args)
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
BINDING_TYPE_dcc (dc_rehash);
static int dc_rehash (struct peer_t *dcc, char *args)
{
  New_Request (dcc->iface, 0, "Rehashing...");
  if (ParseConfig (Config, 0))
    bot_shutdown (BindResult, 3);
  Send_Signal (-1, "*", S_FLUSH);	/* flush all interfaces */
  return 1;
}

		/* .restart */
BINDING_TYPE_dcc (dc_restart);
static int dc_restart (struct peer_t *dcc, char *args)
{
  New_Request (dcc->iface, 0, "Restarting...");
  kill (getpid(), SIGINT);
  return 1;
}

		/* .die [<reason>] */
BINDING_TYPE_dcc (dc_die);
static int dc_die (struct peer_t *dcc, char *args)
{
  char message[MESSAGEMAX];

  if (dcc)
  {
    snprintf (message, sizeof(message), _("Terminated by %s%c %s"),
	      dcc->iface->name, args ? ':' : '.', NONULL(args));
    bot_shutdown (message, 0);
  }
  else
    bot_shutdown (args, 0);
}

		/* .chelp <command> */
BINDING_TYPE_dcc(dc_chelp);
static int dc_chelp(struct peer_t *dcc, char *args)
{
  if (args == NULL || *args == '\0')	/* should have a parameter */
    return 0;
  /* try if usage found first */
  if (Get_Help ("function", args, dcc->iface, dcc->uf, 0, NULL, _("Usage: "), 0))
    return 0;
  /* full help */
  Get_Help ("function", args, dcc->iface, dcc->uf, 0, NULL, NULL, 2);
  return 1;
}

/* ----------------------------------------------------------------------------
 * helpers for client matching
 */

static struct bindtable_t *BT_IsOn = NULL;
static struct bindtable_t *BT_Inspect = NULL;

int Lname_IsOn (const char *net, const char *pub, const char *lname,
		const char **name)
{
  struct binding_t *bind;
  const char *nt;
  struct clrec_t *netw;

  if (!net)
    return 0;
  netw = Lock_Clientrecord (net);
  if (netw)
  {
    if ((Get_Flags (netw, NULL) & U_SPECIAL) &&
	(nt = Get_Field (netw, ".logout", NULL))) /* get network type */
      bind = Check_Bindtable (BT_IsOn, nt, U_ALL, U_ANYCH, NULL);
    else
      bind = NULL;
    Unlock_Clientrecord (netw);
  }
  else
    bind = NULL;
  if (!bind || bind->name)
    return 0;		/* no such network/service */
  return bind->func (net, pub, lname, name);
}

modeflag Inspect_Client (const char *net, const char *pub, const char *name,
			 const char **lname, const char **host, time_t *idle,
			 short *cnt)
{
  struct binding_t *bind;
  const char *nt;
  struct clrec_t *netw;
#define static register
  BINDING_TYPE_inspect_client ((*f));
#undef static

  if (!net)
    return 0;
  netw = Lock_Clientrecord (net);
  if (netw)
  {
    if ((Get_Flags (netw, NULL) & U_SPECIAL) &&
	(nt = Get_Field (netw, ".logout", NULL))) /* get network type */
      bind = Check_Bindtable (BT_Inspect, nt, U_ALL, U_ANYCH, NULL);
    else
      bind = NULL;
    Unlock_Clientrecord (netw);
  }
  else
    bind = NULL;
  if (!bind || bind->name)
    return 0;		/* no such network/service */
  f = (modeflag (*)())bind->func;
  return f (net, pub, name, lname, host, idle, cnt);
}

/* ----------------------------------------------------------------------------
 * main init()
 */

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
  struct binding_t *b = bind;

  if (b)
    FREE (&b->key);
  while (b)
  {
    bind = b->prev;
    FREE (&b);
    b = bind;
  }
}

INTERFACE *init (void)
{
  int g = O_GENERATECONF;
  char new_path[PATH_MAX+FILENAME_LENGTH+2];
  char *msg;
  struct bindtable_t *bt;
  struct binding_t *b;
  INTERFACE *stub;

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
  /* it can be recall of init so don't create another */
  if (!Init)
  {
    Init = Add_Iface (I_INIT, NULL, &_init_sig, &_config_req, NULL);
    Init->ift &= ~I_LOCKED;			/* must be unlocked now! */
  }
  stub = Add_Iface (I_TEMP, NULL, NULL, NULL, NULL);
  Set_Iface (stub);				/* and we want logging */
  /* kill all modules */
  Send_Signal (I_MODULE, "*", S_TERMINATE);
  /* I think I need to destroy trees ? */
  Destroy_Tree (&VTree, free);
  Destroy_Tree (&STree, free);
  /* empty all bindtables */
  for (bt = Tables; bt; bt = bt->next)
  {
    if (bt->type == B_UNIQ || bt->type == B_KEYWORD)
      Destroy_Tree (&bt->list.tree, &_bind_destroy);
    else while (bt->list.bind)
    {
      b = bt->list.bind;
      bt->list.bind = b->next;
      _bind_destroy (b);
    }
  }
  /* init sheduler to have current time, C format now */
  setlocale (LC_TIME, "C");
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
  Unset_Iface();				/* IFInit_DCC() want this */
  if ((msg = IFInit_DCC()))
    bot_shutdown (msg, 3);
  Set_Iface (stub);				/* want full logging again */
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
  if (g != FALSE || O_DEFAULTCONF != FALSE)
  {
    /* reregister all and ask, not write to config yet */
    O_GENERATECONF = TRUE;
    Send_Signal (-1, "*", S_REG);
    _set_floods ();
    /* ask to include any new scripts */
    while (Start_FunctionFromConsole ("script", &cfg_script, "filename"));
    O_GENERATECONF = FALSE;
    /* ending */
  }
  /* before any event, do Wtmp rotating if it needs rotation */
  RotateWtmp();
//
// постэтап - сохранение нового конфига, если указан "-g"
//
  if (g != FALSE)
  {
    struct timespec tp;

    /* give a last chance for threads to get to dispatcher! */
    Unset_Iface();
    tp.tv_sec = 0;
    tp.tv_nsec = 10000000L;
    nanosleep (&tp, NULL);
    /* 0.5a4: moved here */
    /* if generation is true, start new config */
    snprintf (new_path, sizeof(new_path), "%s.new", Config);
    ConfigFileFile = fopen (new_path, "w+");
    if (!ConfigFileFile)
      bot_shutdown (_("Cannot create configuration file."), 3);
    fprintf (ConfigFileFile, "#!%s -q\n# Generated by itself on %s\n", RunPath,
	     ctime (&Time));
    ConfigFileIface = Add_Iface (I_TEMP, NULL, NULL, &_cfile_req, NULL);
    ConfigFileIface->ift = I_TEMP;		/* force flags */
    Set_Iface (ConfigFileIface);		/* it's current again */
    _unsharp_var("charset");
    /* it's time to write to config so signal to register again */
    Send_Signal (-1, "*", S_REG);
    Set_Iface (Init);				/* flush everything now */
    while (Get_Request());
    Unset_Iface();
    _report_floods();
    while (Get_Request());			/* write everything to file */
    /* put all "script" calls to new config */
    if (_Scripts_List)
    {
      fprintf (ConfigFileFile, "%s\n", _Scripts_List);
      FREE (&_Scripts_List);
    }
    fclose (ConfigFileFile);			/* save new config, mode 0700 */
    chmod (new_path, S_IRUSR | S_IWUSR | S_IXUSR);
    unlink (Config);				/* delete old config */
    rename (new_path, Config);
    Unset_Iface();				/* see above */
    Set_Iface (stub);				/* set it current again */
    ConfigFileIface->ift |= I_DIED;		/* delete interface */
    ConfigFileFile = NULL;
    ConfigFileIface = NULL;
  }
  _lock_var ("charset");		/* not changeable anymore */
  foxeye_setlocale();			/* do it BEFORE any case conversions */
  if ((msg = IFInit_Users()))		/* try to load listfile */
    bot_shutdown (msg, 3);
  if (!_load_formats())			/* try to load formats */
    Add_Request (I_LOG, "*", F_BOOT, "Loaded formats file \"%s\"", FormatsFile);
  /* Init have to get signal S_REG so don't kill it */
  Init->IFRequest = NULL;
  O_DEFAULTCONF = FALSE;
  /* check if we going to finish:
      - we have no listen interface nor console nor module;
      - we got "-t" - just testing. */
  if (Find_Iface (I_LISTEN, NULL))
    Unset_Iface();
  else if (Find_Iface (I_CONSOLE, NULL))
    Unset_Iface();
  else if (Find_Iface (I_MODULE, NULL))
    Unset_Iface();
  else
    dc_die (NULL, "terminated: no interfaces to work");
  if (O_TESTCONF != FALSE)
    dc_die (NULL, NULL);
  Add_Binding ("dcc", "binds", U_MASTER, U_MASTER, (Function)&dc_binds, NULL);
  Add_Binding ("dcc", "module", U_OWNER, U_NONE, (Function)&dc_module, NULL);
  Add_Binding ("dcc", "status", U_MASTER, U_NONE, (Function)&dc_status, NULL);
  Add_Binding ("dcc", "fset", U_OWNER, U_NONE, (Function)&dc_fset, NULL);
  Add_Binding ("dcc", "rehash", U_MASTER, U_NONE, &dc_rehash, NULL);
  Add_Binding ("dcc", "restart", U_MASTER, U_NONE, &dc_restart, NULL);
  Add_Binding ("dcc", "die", U_OWNER, U_NONE, &dc_die, NULL);
  Add_Binding ("dcc", "set", U_MASTER, U_MASTER, &dc_set, NULL);
  Add_Binding ("dcc", "chelp", U_OWNER, U_NONE, &dc_chelp, NULL);
  Unset_Iface();				/* out of stub */
  stub->ift = I_DIED;
  return (Init);
}
