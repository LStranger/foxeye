/*
 * Copyright (C) 1999-2010  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is part of FoxEye's source: the help layer.
 */

#include "foxeye.h"

#include "init.h"
#include "tree.h"

#define HELPFILEMAXSIZE 131072	/* max size = 128k */

static char *EOL (const char *s)
{
  return strpbrk (s, "\r\n");
}

typedef struct HELP
{
  char *key;			/* lower case */
  char *data;
  void *helpgr;
  struct HELP *next;		/* in helpfile */
} HELP;

typedef struct HELPGR
{
  char *key;			/* case-insensitive */
  NODE *tree;
  struct HELPGR *next;
} HELPGR;

typedef struct HELPFILE
{
  char *name;			/* matchcase */
  HELP *help;			/* first element */
  char *hfile;
  struct HELPFILE *next;
} HELPFILE;

static HELPGR *Help = NULL;
static HELPFILE *HFiles = NULL;

static HELPGR *_get_helpgr (char *name)
{
  HELPGR *h = NULL;			/* compiler lies about uninitialized */
  HELPGR *gr = Help;

  for (; gr; gr = gr->next)
  {
    if (!safe_strcasecmp (gr->key, name))
      return gr;
    h = gr;				/* last group */
  }
  gr = safe_calloc (1, sizeof(HELPGR));
  gr->key = safe_strdup (name);
  if (Help)
    h->next = gr;
  else
    Help = gr;
  return gr;
}

int Add_Help (const char *name)
{
  char path[LONG_STRING];
  FILE *fp = NULL;
  long size;
  HELPFILE **hf;
  HELP **ht;
  char *data, *endc = NULL;
  char *key, *gr = NULL;
  register char *c;
  size_t s = 0;				/* compiler lies about uninitialized */

  /* check if file.$locale exist */
  if (*locale)
  {
    snprintf (path, sizeof(path), "%s/%s.%s", HELPDIR, name, locale);
    fp = fopen (path, "r");
    /* check if file.$lang exists */
    if (!fp)
    {
      snprintf (path, sizeof(path), "%s/%s.%.2s", HELPDIR, name, locale);
      fp = fopen (path, "r");
    }
  }
  /* check for default helpfile */
  if (!fp)
  {
    snprintf (path, sizeof(path), "%s/%s", HELPDIR, name);
    fp = fopen (path, "r");
  }
  /* last try: check if file.C exist */
  if (!fp)
  {
    snprintf (path, sizeof(path), "%s/%s.C", HELPDIR, name);
    fp = fopen (path, "r");
  }
  if (!fp)
  /* may be it have to print error message? */
    return 0;
  /* scan the file for topics */
  fseek (fp, 0L, SEEK_END);
  size = ftell (fp);
  if (size < 0 || size > HELPFILEMAXSIZE)
  {
    Add_Request (I_LOG, "*", F_BOOT, "Cannot load help file: illegal size");
    fclose (fp);
    return 0;
  }
  fseek (fp, 0L, SEEK_SET);
  for (hf = &HFiles; *hf; hf = &(*hf)->next);	/* find the tail */
  *hf = safe_calloc (1, sizeof(HELPFILE));
  (*hf)->hfile = safe_malloc ((size_t)size + 1);
  if (fread ((*hf)->hfile, 1, (size_t)size, fp) != (size_t)size)
  {
    Add_Request (I_LOG, "*", F_BOOT, "Help file reading error!");
    fclose (fp);
    FREE (&(*hf)->hfile);
    FREE (hf);
    return 0;
  }
  fclose (fp);
  (*hf)->name = safe_strdup (name);
  (*hf)->next = NULL;
  Add_Request (I_LOG, "*", F_BOOT, "Loading helpfile %s", path);
  (*hf)->hfile[(size_t)size] = 0;
  ht = &(*hf)->help;
  data = (*hf)->hfile;
  c = NULL;
  /* HELPGR "" must be first */
  _get_helpgr (NULL);
  do
  {
    switch (*data)
    {
      /* body */
      case ':':
	if (gr)
	{
	  (*ht)->data = c = data;
	  data++;			/* skip ':' for first topic */
	  gr = NULL;
	}
	s = 0;
      case ' ':
      case '\t':
	endc = EOL (data);
	if (c)				/* there is data topic yet? */
	{
	  if (s)			/* need to join to previous line? */
	    while (*data == ' ' || *data == '\t') data++;
	  else
	    *c++ = '\n';		/* line starts from '\n' */
	  if (endc)
	    s = endc - data;
	  else
	    s = strlen (data);
	  if (s)
	  {
	    memmove (c, data, s);
	    c += s;
	    if (*(c-1) == '\\')
	    {
	      *(c-1) = ' ';
	      s = 1;
	    }
	    else
	      s = 0;
	  }
	}
	break;
      /* comment */
      case '\r':
      case '\n':
      case '#':
	endc = EOL (data);
	break;
      /* key */
      default:
	if (c)				/* topics terminator */
	  *c = 0;
	if (*ht)
	  ht = &(*ht)->next;
	*ht = safe_calloc (1, sizeof(HELP));
	gr = data;
	endc = EOL (data);
	c = NULL;
	if (endc && *endc)
	  *endc++ = 0;
	key = NextWord (data);
	while (*data && *data != ' ') data++;
	*data = 0;
	if (!*key)
	{
	  key = gr;
	  (*ht)->helpgr = Help;
	}
	else
	  (*ht)->helpgr = _get_helpgr (gr);
	(*ht)->key = key;
	if (Insert_Key (&((HELPGR *)(*ht)->helpgr)->tree, key, *ht, 1))
	  WARNING ("help: duplicate entry \"%s\" for set \"%s\" ignored", key,
		   gr == key ? "" : gr);
	else
	  dprint (2, "help: adding entry for \"%s\" to set \"%s\"", key,
		  gr == key ? "" : gr);
    }
    data = endc;
    if (data && *data == '\r')
      data++;
    if (data && *data == '\n')
      data++;
  } while (data && data < (*hf)->hfile + size);
  if (c)				/* topics terminator */
    *c = 0;
  return 1;
}

void Delete_Help (const char *name)
{
  HELPFILE *h, *hp = NULL;
  HELP *t, *next = NULL;

  /* find the file */
  for (h = HFiles; h; hp = h, h = h->next)
  {
    if (!safe_strcmp (name, h->name))
      break;
  }
  if (!h)
    return;
  if (hp)
    hp->next = h->next;
  else
    HFiles = h->next;
  /* delete keys from groups */
  for (t = h->help; t; t = next)
  {
    next = t->next;
    Delete_Key (((HELPGR *)t->helpgr)->tree, t->key, t);
    dprint (2, "help: deleting entry for \"%s\" from set \"%s\"", t->key,
	    NONULL(((HELPGR *)t->helpgr)->key));
    FREE (&t);
  }
  Add_Request (I_LOG, "*", F_BOOT, "Unloaded helpfile %s", name);
  /* free memory */
  FREE (&h->hfile);
  FREE (&h->name);
  FREE (&h);
}

static int _no_such_help (INTERFACE *iface, int mode)
{
  if (mode >= 0)
    New_Request (iface, 0, _("No help on this."));
  return 0;
}

#define HELP_LINE_SIZE 72

static int _help_one_topic (char *text, INTERFACE *iface, char *prefix,
			    const char *gr, const char *topic, int mode)
{
  char buff[HUGE_STRING];
  char *c, *end;

  if (mode > 2 || mode < 0)		/* ugly mode? */
    mode = 0;
  /* select a part */
  for (; mode; )
  {
    text = strchr (text, '\n');
    if (text)
      text++;
    else
      return _no_such_help (iface, mode);
    if (*text == ':')
      mode--;
  }
  c = text++;
  while ((c = strchr (c, '\n')))	/* get to next part */
  {
    if (c[1] == ':')
      break;
    else
      c++;				/* skip '\n' */
  }
  if (c)
    *c = 0;
  /* convert the line */
  if (gr && *gr)
  {
    char tbuf[STRING];

    snprintf (tbuf, sizeof(tbuf), "%s %s", gr, topic);
    printl (buff, sizeof(buff), text, HELP_LINE_SIZE,
	    iface->name, NULL, NULL, NULL, 0L, 0, 0, tbuf);
  }
  else
    printl (buff, sizeof(buff), text, HELP_LINE_SIZE,
	    iface->name, NULL, NULL, NULL, 0L, 0, 0, topic);
  if (c)
    *c = '\n';
  /* print out - line by line - only if there is something to out */
  if (buff[0]) for (c = buff; c; c = end)
  {
    end = strchr (c, '\n');
    if (end)
      *end++ = 0;
    /* may be, align all text with spaces here? :) */
    New_Request (iface, 0, "%s%s", prefix, c);
    prefix = "  ";			/* indent next line :) */
  }
  return 1;
}

static int _help_all_topics (HELPGR *what, INTERFACE *iface, userflag gf,
			     userflag cf, struct bindtable_t *table, int mode)
{
  const char *key;
  LEAF *leaf = NULL;
  char buf[HELP_LINE_SIZE+2];
  size_t s = 0, ns;
  int r = 0;

  while ((leaf = Next_Leaf (what->tree, leaf, &key)))
  {
    if (Check_Bindtable (table, key, gf, cf, NULL) != NULL)
    {
      /* this is first? */
      if (!r)
      {
	/* mode dependent message? */
	New_Request (iface, 0, _("Available topics for \"help%s%s\":"),
		    what->key ? " " : "", what->key ? what->key : "");
      }
      r++;
      /* try to add to buf */
      ns = safe_strlen (key);
      if (s + ns >= HELP_LINE_SIZE)
      {
	if (s)
	{
	  New_Request (iface, 0, "%s", buf);
	  s = 0;
	}
	if (ns >= HELP_LINE_SIZE)
	{
	  New_Request (iface, 0, "%s", key);
	  continue;
	}
      }
      if (s)
	buf[s++] = ' ';
      strfcpy (&buf[s], key, ns + 1);
      s += ns;
    }
  }
  if (s)
    New_Request (iface, 0, "%s", buf);
  return r;
}

int Get_Help (const char *fst, const char *sec, INTERFACE *iface, userflag gf,
	      userflag cf, struct bindtable_t *table, char *prefix, int mode)
{
  const char *topic = NONULL(sec);	/* default topic=fst{sec} */
  HELPGR *h = Help;
  HELP *t;

  dprint (4, "help:Get_Help: call \"%s %s\"", NONULL(fst), NONULL(sec));
  if (!h)
    return _no_such_help (iface, mode);		/* no help loaded */
  else if (!table)
  {
    if (!fst)
      return _no_such_help (iface, mode);	/* NULL/smth : no table */
  }
  else if (!fst && *topic)					/* NULL smth */
  {
    if (strcmp (topic, "*") &&					/* NULL !"*" */
	Check_Bindtable (table, sec, gf, cf, NULL) == NULL)
      return _no_such_help (iface, mode);	/* NULL/name : not found */
    fst = Bindtable_Name (table);		/* -> table/name */
  }
  else if (!fst || !*fst || !strcmp (fst, "*"))			/* "*" NULL */
    return _help_all_topics (Help, iface, gf, cf, table, mode);
  else if (Check_Bindtable (table, fst, gf, cf, NULL) == NULL)	/* smth "*" */
    return _no_such_help (iface, mode);		/* no fst in table */
  /* check for group first - if is second parameter! */
  if (!*topic)					/* if fst/NULL */
    topic = fst;			/* then topic=fst{fst} */
  else for (; h; h = h->next)			/* smth/name */
  {
    if (!safe_strcasecmp (h->key, fst))
      break;
  }
  /* no such group? */
  if (!h)
  {
    WARNING ("help: set \"%s\" not found", fst);
    if (sec && *sec)
      return _no_such_help (iface, mode);	/* BAD/smth */
    /* find common help */
    h = Help;					/* if smth/NULL */
  }
  if (table && !strcmp (topic, "*"))		/* if topic is ...{*} */
    return _help_all_topics (h, iface, gf, cf, table, mode);
  t = Find_Key (h->tree, topic);
  if (!t)
  {
    WARNING ("help: topic \"%s\" not found", topic);
    if (table && h != Help && !sec)		/* table/NULL */
      return _help_all_topics (h, iface, gf, cf, table, mode);
    return _no_such_help (iface, mode);
  }
  dprint (3, "help: found entry for \"%s\" in set \"%s\"", topic, NONULL(h->key));
  return _help_one_topic (t->data, iface, NONULL(prefix), h->key, topic, mode);
}
