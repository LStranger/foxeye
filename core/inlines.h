/*
 * Copyright (C) 1996-8 Michael R. Elkins <me@cs.hmc.edu>
 * Copyright (C) 1999 Thomas Roessler <roessler@guug.de>
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
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This file is part of FoxEye's source: common simple functions.
 * They have to be included either in lib.c or in protos.h if compiler
 * supports inline directive
 */

#ifdef _INLINES_H
# error File inlines.h can be included only once!
#endif
#define _INLINES_H 1

/* in case it's included into protos.h it has to be declared static */
#ifdef HAVE_INLINE
# define INLINE_I static inline
# define INLINE __attribute__((warn_unused_result)) static inline
#else
# define INLINE_I
# define INLINE
#endif

INLINE int safe_strcmp(const char *a, const char *b)
{
  return strcmp(NONULL(a), NONULL(b));
}

INLINE int safe_strcasecmp(const char *a, const char *b)
{
  return strcasecmp(NONULL(a), NONULL(b));
}

INLINE int safe_strncmp(const char *a, const char *b, size_t l)
{
  return strncmp(NONULL(a), NONULL(b), l);
}

INLINE int safe_strncasecmp(const char *a, const char *b, size_t l)
{
  return strncasecmp(NONULL(a), NONULL(b), l);
}

INLINE size_t safe_strlen(const char *a)
{
  return a ? strlen (a) : 0;
}

INLINE char *safe_strdup (const char *s)
{
  char *p;
  size_t l;

  if (!s || !*s) return NULL;
  l = safe_strlen (s) + 1;
  p = (char *)safe_malloc (l);
  memcpy (p, s, l);
  return (p);
}

INLINE_I char *strfcat (char *dst, const char *src, size_t n)
{
  register size_t n1;

  if (!n || !dst)
    return NULL;
  n1 = strlen (dst);
  n--;
  if (!src || n1 >= n)
    return dst;
  dst[n] = 0;			/* terminate dst */
  strncpy (&dst[n1], src, n - n1);
  return dst;
}

INLINE char *safe_strchr (char *s, int c)
{
  register char *r = s;
  register char ch = c;

  if (r)
  {
    for (; *r && *r != ch; r++);
    if (*r == 0)
      r = NULL;
  }
  return r;
}

INLINE char *NextWord (char *msg)
{
  if (msg == NULL) return msg;
  while (*msg && *msg != ' ') msg++;
  while (*msg == ' ') msg++;
  return msg;
}

INLINE_I char *NextWord_Unquoted (char *name, char *line, size_t s)
{
  register char *c;
  char ch;

  if ((c = line) == NULL)
    return NULL;
  if (*c == '"')
  {
    ch = '"';
    c++;
  }
  else
    ch = ' ';
  while (*c)
  {
    if (*c == ch && (ch != '"' || *(++c) != '"'))
      break;
    if (s > 1)
    {
      *name++ = *c;
      s--;
    }
    c++;
  }
  if (s)
    *name = 0;
  while (*c == ' ') c++;
  return c;
}

INLINE_I void StrTrim (char *cmd)
{
  register char *ch;

  if (!cmd)
    return;
  for (ch = &cmd[strlen(cmd)]; ch >= cmd; ch--)
    if (*ch && !strchr (" \r\n", *ch))
      break;
  if (ch < cmd || *ch)
    ch[1] = 0;
}

INLINE const char *expand_path (char *buf, const char *str, size_t s)
{
  if (safe_strncmp (str, "~/", 2))
    return str;
  snprintf (buf, s, "%s/%s", getenv ("HOME"), &str[2]);
  return buf;
}

INLINE char *gettoken (char *ptr, char **eow)
{
  register char *c = ptr;

  if ((*c & 0xdf) != 0) FOREVER		/* cycle a long word */
  {
    if ((*++c & 0xdf) == 0)		/* 0x0 or 0x20, i.e. '\0' or ' ' */
      break;
    if ((*++c & 0xdf) == 0)
      break;
    if ((*++c & 0xdf) == 0)
      break;
    if ((*++c & 0xdf) == 0)
      break;
  }
  if (eow)
    *eow = c;				/* give it to caller */
  if (*c)				/* check for EOL */
  {
    *c = 0;				/* terminate it */
    while (*++c == ' ');		/* go to next word */
  }
  return c;
}

/* cleanup */
#undef INLINE_I
#undef INLINE
