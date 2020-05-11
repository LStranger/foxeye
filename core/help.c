/*
 * Copyright (C) 1999-2020  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This file is part of FoxEye's source: the help layer.
 */

#include "foxeye.h"

#include <fcntl.h>

#include "init.h"
#include "tree.h"
#include "conversion.h"

#define HELPFILEMAXSIZE 131072	/* max size = 128k */

static char *EOL (const char *s)
{
  return strpbrk (s, "\r\n");
}

typedef struct HELPGR HELPGR;
typedef struct HELPLANG HELPLANG;

typedef struct HELP
{
  char *key;			/* lower case */
  char *data;
  HELPGR *helpgr;
  struct HELP *next;		/* in helpfile */
} HELP;

typedef struct HELPLGR
{
  struct HELPLGR *next;
  HELPLANG *lang;
  NODE *tree;
} HELPLGR;

struct HELPGR
{
  char *key;			/* case-insensitive */
  NODE *tree;			/* C lang */
  HELPLGR *langs;
  HELPGR *next;
};

typedef struct HELPFILE
{
  char *name;			/* matchcase */
  HELP *help;			/* first element */
  char *hfile;
  struct HELPFILE *next;
} HELPFILE;

struct HELPLANG
{
  HELPLANG *next;
  char *lang;			/* matchcase */
  HELPFILE *files;
};

static HELPGR *Help = NULL;
static HELPLANG *HLangs = NULL;

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
  dprint(5, "added set \"%s\" to help", name);
  return gr;
}

static int Add_Help_L (const char *name, const char *lang)
{
  char path[LONG_STRING];
  int fd = -1;
  off_t size;
  HELPLANG **hl;
  HELPFILE **hf;
  HELP **ht;
  NODE **tree;
  HELPLGR **hlgr;
  char *data, *endc = NULL;
  char *key, *gr = NULL;
  register char *c;
  size_t s = 0;				/* compiler lies about uninitialized */

  /* check if lang was already loaded */
  for (hl = &HLangs; *hl; hl = &(*hl)->next)
    if (safe_strcmp((*hl)->lang, lang) == 0)
      break;
  /* create new lang if it does not exist */
  if (*hl == NULL)
  {
    *hl = safe_calloc(1, sizeof(HELPLANG));
    (*hl)->lang = safe_strdup(lang);
  }
  /* check if name was already loaded for lang */
  for (hf = &(*hl)->files; *hf; hf = &(*hf)->next)
    if (safe_strcmp((*hf)->name, name) == 0)
      break;
  if (*hf)
    /* already loaded, return success */
    return 1;
  /* check if file.$lang exists */
  if (lang && *lang)
  {
    snprintf (path, sizeof(path), "%s/%s.%s", HELPDIR, name, lang);
    fd = open (path, O_RDONLY);
    /* check if file.$lang exists */
    if (fd < 0)
    {
      snprintf (path, sizeof(path), "%s/%s.%.2s", HELPDIR, name, lang);
      fd = open (path, O_RDONLY);
    }
  }
  else
  /* check for default helpfile */
  {
    lang = "";
    snprintf (path, sizeof(path), "%s/%s", HELPDIR, name);
    fd = open (path, O_RDONLY);
    /* last try: check if file.C exists */
    if (fd < 0)
    {
      snprintf (path, sizeof(path), "%s/%s.C", HELPDIR, name);
      fd = open (path, O_RDONLY);
    }
  }
  if (fd < 0)
  /* may be it have to print error message? */
    return 0;
  /* scan the file for topics */
  size = lseek (fd, (off_t)0, SEEK_END);
  if (size < 0 || size > HELPFILEMAXSIZE)
  {
    Add_Request (I_LOG, "*", F_BOOT, "Cannot load help file: illegal size");
    close (fd);
    return 0;
  }
  lseek (fd, (off_t)0, SEEK_SET);
  *hf = safe_calloc (1, sizeof(HELPFILE));
  (*hf)->hfile = safe_malloc ((size_t)size + 1);
  if (read (fd, (*hf)->hfile, (size_t)size) != (ssize_t)size)
  {
    Add_Request (I_LOG, "*", F_BOOT, "Help file reading error!");
    close (fd);
    FREE (&(*hf)->hfile);
    FREE (hf);
    return 0;
  }
  close (fd);
  (*hf)->name = safe_strdup (name);
  (*hf)->next = NULL;
  Add_Request (I_LOG, "*", F_BOOT, "Loading helpfile %s", path);
  (*hf)->hfile[(size_t)size] = 0;
  ht = &(*hf)->help;
  data = (*hf)->hfile;
  if (memcmp(data, "##$charset ", 11) == 0) {
    struct conversion_t *conv;
    char *newdata;
    size_t convsz, leftsz;
    register size_t ptr;

    key = c = NextWord(&data[10]);
    while (*c && *c != ' ' && *c != '\r' && *c != '\n') c++;
    if (*c)
      *c++ = '\0';
    while (*c && *c != '\r' && *c != '\n') c++;
    if (*c)
      *c++ = '\0';
    size -= (c - data);
    data = c;
    conv = Get_Conversion(key);
    convsz = s = 0;
    leftsz = (size_t)size;
    newdata = NULL;
    if (conv != NULL) {
      while (leftsz) {
	convsz += HUGE_STRING;
	dprint(5, "help.c: converting help: preserving %zu memory", convsz);
	safe_realloc((void **)&newdata, convsz);
	key = &newdata[s];	/* it's changed on realloc */
	ptr = (size_t)size - leftsz;
	ptr = Do_Conversion(conv, &key, convsz - s - 1, &data[ptr], &leftsz);
	if (ptr == 0) {
	  ERROR("help.c: unrecoverable conversion error in %s", path);
	  break;
	} else if (key != &newdata[s]) { /* Get_Conversion failed? */
	  ERROR("help.c: unknown conversion descriptor error");
	  FREE(&newdata);
	  break;
	}
	s += ptr;
      }
      if (newdata != NULL) {
	FREE(&data);
	(*hf)->hfile = data = newdata;
	size = s;
	data[s] = '\0';
      }
      Free_Conversion(conv);
    }
  }
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
	  if (*data == ' ' || *data == '\t')
	    data++;			/* skip first space char */
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
	if (*lang)
	{
	  for (hlgr = &(*ht)->helpgr->langs; *hlgr; hlgr = &(*hlgr)->next)
	    if ((*hlgr)->lang == *hl)
	      break;
	  if (*hlgr == NULL)
	  {
	    *hlgr = safe_calloc(1, sizeof(HELPLGR));
	    (*hlgr)->lang = *hl;
	  }
	  tree = &(*hlgr)->tree;
	}
	else
	  tree = &(*ht)->helpgr->tree;
	if (Insert_Key (tree, key, *ht, 1))
	  WARNING ("help: duplicate entry \"%s\" for set \"%s\" in lang \"%s\" ignored",
		   key, gr == key ? "" : gr, lang);
	else
	  dprint (2, "help: adding entry for \"%s\" to set \"%s\" in lang \"%s\"",
		  key, gr == key ? "" : gr, lang);
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

int Add_Help (const char *name)
{
  int ret;
  HELPLANG *hl;

  if (HLangs == NULL)
    return Add_Help_L (name, NULL);
  else for (ret = 0, hl = HLangs; hl; hl = hl->next)
    /* scan files for all already loaded languages */
    if (Add_Help_L (name, hl->lang))
      ret = 1;
  return ret;
}

static void _delete_help_lang(HELPLANG *hl, const char *name)
{
  HELPFILE *h, **hp;
  HELP *t;
  HELPLGR *lgr;
  NODE *tree;

  /* find the file */
  for (hp = &hl->files; (h = *hp); hp = &h->next)
  {
    if (!safe_strcmp (name, h->name))
      break;
  }
  if (!h)
    return;
  *hp = h->next;
  /* delete keys from groups */
  while ((t = h->help))
  {
    h->help = t->next;
    if (hl->lang) {
      for (lgr = t->helpgr->langs; lgr; lgr = lgr->next)
	if (lgr->lang == hl)
	  break;
      if (lgr == NULL)
      {
	/* this should never happen! */
	ERROR("help: lang \"%s\" not found in set \"%s\"!", hl->lang,
	      NONULL(t->helpgr->key));
	FREE (&t);
	continue;
      }
      tree = lgr->tree;
    } else
      tree = t->helpgr->tree;
    Delete_Key (tree, t->key, t);
    dprint (2, "help: deleting entry for \"%s\" from set \"%s\" in lang \"%s\"",
	    t->key, NONULL(t->helpgr->key), NONULL(hl->lang));
    FREE (&t);
  }
  Add_Request (I_LOG, "*", F_BOOT, "Unloaded helpfile %s (lang \"%s\")", name,
	       NONULL(hl->lang));
  /* free memory */
  FREE (&h->hfile);
  FREE (&h->name);
  FREE (&h);
}

void Delete_Help (const char *name)
{
  HELPLANG *hl;

  /* process in each lang */
  for (hl = HLangs; hl; hl = hl->next)
    _delete_help_lang(hl, name);
}

/* tries to load language */
static HELPLANG *_help_load_lang(const char *lang)
{
  HELPLANG *hl, **hlp;
  HELPFILE *hf;

  for (hlp = &HLangs; (hl = *hlp); hlp = &hl->next)
    if (safe_strcmp(hl->lang, lang) == 0)
      break;
  if (hl == NULL && HLangs != NULL)
  {
    /* if not found then search and load $name.$lang for all added helpfiles */
    *hlp = hl = safe_calloc(1, sizeof(HELPLANG));
    hl->lang = safe_strdup(lang);
    for (hf = HLangs->files; hf; hf = hf->next)
      Add_Help_L(hf->name, lang);
  }
  return hl;
}

static int _no_such_help (INTERFACE *iface, const char *prefix, int each, int mode)
{
  if (mode < 0 || each < 0) ;
  else if (each && prefix)
    New_Request (iface, 0, "%s%s", prefix, _("No help on this."));
  else
    New_Request (iface, 0, _("No help on this."));
  return 0;
}

#define HELP_LINE_SIZE 72

static int _help_one_topic (char *text, INTERFACE *iface, const char *prefix,
			    int each, const char *gr, const char *topic, int mode)
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
      return _no_such_help (iface, prefix, each, mode);
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
    if (!each)
      prefix = "  ";			/* indent next line :) */
  }
  return 1;
}

static int _help_all_topics (HELPGR *what, INTERFACE *iface, userflag gf,
			     userflag cf, struct bindtable_t *table, int mode,
			     const char *prefix, int each)
{
  const char *key;
  LEAF *leaf = NULL;
  struct binding_t *b;
  char buf[HELP_LINE_SIZE+2];
  size_t s = 0, ns;
  int r = 0;

  while ((leaf = Next_Leaf (what->tree, leaf, &key)))
  {
    if ((b = Check_Bindtable (table, key, gf, cf, NULL)) != NULL)
    {
      if (strcmp(key, b->key))		/* it's matched but just similar */
	continue;
      /* is this first? */
      if (!r && each == 0)
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
	  New_Request (iface, 0, "%s%s", (each && prefix) ? prefix : "", buf);
	  s = 0;
	}
	if (ns >= HELP_LINE_SIZE)
	{
	  New_Request (iface, 0, "%s%s", (each && prefix) ? prefix : "", key);
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
    New_Request (iface, 0, "%s%s", (each && prefix) ? prefix : "", buf);
  return r;
}

#ifndef ENABLE_NLS
static
#endif
int Get_Help_L (const char *fst, const char *sec, INTERFACE *iface, userflag gf,
		userflag cf, struct bindtable_t *table, const char *prefix,
		int each, int mode, const char *lang)
{
  const char *topic = NONULL(sec);	/* default topic=fst{sec} */
  HELPGR *h = Help;
  HELP *t = NULL;
  HELPLANG *hl;
  HELPLGR *hlgr;

  dprint (5, "help:Get_Help: call \"%s %s\"", NONULL(fst), NONULL(sec));
  if (!h)
    return _no_such_help (iface, prefix, each, mode);	/* no help loaded */
  else if (!table)
  {
    if (!fst)
      return _no_such_help (iface, prefix, each, mode);	/* NULL/smth : no table */
  }
  else if (!fst && *topic)					/* NULL smth */
  {
    if (strcmp (topic, "*") &&					/* NULL !"*" */
	Check_Bindtable (table, sec, gf, cf, NULL) == NULL)
      return _no_such_help (iface, prefix, each, mode);	/* NULL/name : not found */
    fst = Bindtable_Name (table);		/* -> table/name */
  }
  else if (!fst || !*fst || !strcmp (fst, "*"))			/* "*" NULL */
    return _help_all_topics (Help, iface, gf, cf, table, mode, prefix, each);
  else if (*fst == '=')
  {
    if (Check_Bindtable (table, topic, gf, cf, NULL) == NULL)
      return _no_such_help (iface, prefix, each, mode);
  }
  else if (Check_Bindtable (table, fst, gf, cf, NULL) == NULL)	/* smth "*" */
    return _no_such_help (iface, prefix, each, mode);	/* no fst in table */
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
    dprint (4, "help: set \"%s\" not found", fst);
    if (sec && *sec)
      return _no_such_help (iface, prefix, each, mode);	/* BAD/smth */
    /* find common help */
    h = Help;					/* if smth/NULL */
  }
  if (table && !strcmp (topic, "*"))		/* if topic is ...{*} */
    return _help_all_topics (h, iface, gf, cf, table, mode, prefix, each);
  if (lang && *lang)
  {
    hl = _help_load_lang(lang);
    for (hlgr = h->langs; hlgr; hlgr = hlgr->next)
      if (hlgr->lang == hl)
	break;
    if (hlgr)
      t = Find_Key (hlgr->tree, topic);
  }
  if (t == NULL)
    t = Find_Key (h->tree, topic);
  if (!t)
  {
    dprint (4, "help: topic \"%s\" not found", topic);
    if (table && h != Help && !sec)		/* table/NULL */
      return _help_all_topics (h, iface, gf, cf, table, mode, prefix, each);
    return _no_such_help (iface, prefix, each, mode);
  }
  dprint (4, "help: found entry for \"%s\" in set \"%s\"", topic, NONULL(h->key));
  return _help_one_topic (t->data, iface, NONULL(prefix), each, h->key, topic, mode);
}

int Get_Help (const char *fst, const char *sec, INTERFACE *iface, userflag gf,
	      userflag cf, struct bindtable_t *table, const char *prefix, int mode)
{
  return Get_Help_L (fst, sec, iface, gf, cf, table, prefix, 0, mode, locale);
}
