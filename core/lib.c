/*
 * Copyright (C) 1996-8 Michael R. Elkins <me@cs.hmc.edu>
 * Copyright (C) 1999 Thomas Roessler <roessler@guug.de>
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
 * This file is part of FoxEye's source: common functions library.
 */

#include "foxeye.h"
#include "init.h"

#include <ctype.h>
#include <sys/utsname.h>
#include <wchar.h>
#include <locale.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* simple functions have to be either here or in protos.h
   if compiler supports inline directive */
#ifndef HAVE_INLINE
# include "inlines.h"
#endif

static char *mem_msg = N_("Out of memory!");

void *safe_calloc (size_t nmemb, size_t size)
{
  void *p;

  if (!nmemb || !size)
    return NULL;
  if (!(p = calloc (nmemb, size)))
    bot_shutdown (mem_msg, 2);
  DBG ("safe_calloc(%zu*%zu)=0x%08lx", nmemb, size, (long int)p);
  return p;
}

void *safe_malloc (size_t siz)
{
  void *p;

  if (siz == 0)
    return NULL;
  if ((p = (void *) malloc (siz)) == 0)
    bot_shutdown (mem_msg, 2);
  DBG ("safe_malloc(%zu)=0x%08lx", siz, (long int)p);
  return p;
}

void safe_realloc (void **p, size_t siz)
{
  void *r;

  if (siz == 0)
  {
    DBG ("safe_realloc(0x%08lx,0)", (long int)*p);
    if (*p)
    {
      free (*p);
      *p = NULL;
    }
    return;
  }

  if (*p)
    r = (void *) realloc (*p, siz);
  else
  {
    /* realloc(NULL, nbytes) doesn't seem to work under SunOS 4.1.x */
    r = (void *) malloc (siz);
  }
  if (!r)
    bot_shutdown (mem_msg, 2);
  DBG ("safe_realloc(0x%08lx,%zu)=0x%08lx", (long int)*p, siz, (long int)r);
  *p = r;
}

void safe_free (void **p)
{
  if (*p)
  {
    DBG ("safe_free(0x%08lx)", (long int)*p);
    free (*p);
    *p = NULL;
  }
}


/*
 * converts null-terminated string src to upper case string
 * output buffer dst with size ds must be enough for null-terminated string
 * else string will be truncated
 * returns length of output null-terminated string (without null char)
 * if dst == NULL or ds == 0 then returns 0
*/
size_t unistrlower (char *dst, const char *src, size_t ds)
{
  size_t sout = 0, ss;

  if (dst == NULL || ds == 0)
    return 0;
  ds--; /* preserve 1 byte for terminating null char */
  if (src && *src)
  {
    if (MB_CUR_MAX > 1) /* if multibyte encoding */
    {
      wchar_t wc;
      register ssize_t len;
      const char *ch;
      mbstate_t ms;
      char replace_char = *text_replace_char;
      char c[MB_LEN_MAX];

      memset(&ms, 0, sizeof(ms)); /* reset the state */
      for (ch = src, ss = strlen(ch); *ch && ds > 0; )
      {
	len = mbrtowc(&wc, ch, ss, &ms);
	if (len < 1) /* unrecognized char! */
	{
	  if (replace_char)
	  {
	    *dst++ = replace_char; /* OK, we replace it then */
	    sout++;
	    ds--;
	  }
	  if (len == -2) /* premature end of string */
	    break;
	  ss--;
	  ch++; /* and skip bad char */
	  memset(&ms, 0, sizeof(ms)); /* reset the state */
	  continue;
	}
	ss -= len; /* advance pointer in sourse string */
	ch += len;
	wc = towlower(wc);
	len = wcrtomb(c, wc, &ms); /* first get the size of lowercase mbchar */
	if (len < 1)
	  continue; /* tolower() returned unknown char? ignore it */
	if (len > (ssize_t)ds)
	  break; /* oops, out of output size! */
	memcpy(dst, c, len); /* really convert it */
	ds -= len; /* advance pointers in destination string */
	dst += len;
	sout += len;
      }
    }
    else
    { /* string in internal single-byte encoding the same as locale */
      register char ch;

      for (ch = *src++; ch && ds; ch = *src++, sout++, ds--)
	*dst++ = tolower((unsigned char)ch);
    }
  }
  *dst = 0;
  return (sout);
}

static bool _charset_is_utf = FALSE;

void foxeye_setlocale (void)
{
  int changed = 1;
  char new_locale[SHORT_STRING];

  snprintf (new_locale, sizeof(new_locale), "%s.%s", locale, Charset);
  DBG ("current locale is %s", setlocale (LC_ALL, NULL));
  DBG ("trying set locale to %s", new_locale);
  if (setlocale (LC_ALL, new_locale) == NULL)
  {
    _charset_is_utf = FALSE;
    snprintf (new_locale, sizeof(new_locale), "%s.%s", locale, CHARSET_8BIT);
    if (setlocale (LC_ALL, new_locale) == NULL)
    {
      char *c, *deflocale;

      deflocale = setlocale (LC_ALL, "");
      ERROR ("init: failed to set locale to %s, reverted to default %s!",
	     new_locale, deflocale);
      c = safe_strchr (deflocale, '.');
      if (c)
	strfcpy (Charset, ++c, sizeof(Charset)); /* reset charset */
      changed = 0;
    }
    else
    {
      ERROR ("init: failed to set locale to %s.%s, reverted to %s!", locale,
	     Charset, new_locale);
      strfcpy (Charset, CHARSET_8BIT, sizeof(Charset)); /* reset charset */
    }
  }
  else if (!strncasecmp (Charset, "utf", 3))
    _charset_is_utf = TRUE;
  else
    _charset_is_utf = FALSE;
  if (changed)
    setenv("LC_ALL", new_locale, 1); /* reset environment */
#ifdef ENABLE_NLS
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif
}

/*
 * checks null-terminated string in line to contain not more than:
 *  - len bytes (including termination byte)
 *  - maxchars characters (without null char)
 * returns size of string to be truncated in bytes without null char
 */
size_t unistrcut (const char *line, size_t len, int maxchars)
{
  len--;			/* preserve 1 byte for '\0' */
  if (_charset_is_utf == TRUE)	/* let's count chars - works for utf* only */
  {
    register unsigned char *ch = (unsigned char *)line;
    unsigned char *chmax = (unsigned char *)&line[len];
    register size_t cursize;
    register int chsize = maxchars;

    while (chsize > 0 && ch < chmax && *ch) /* go for max chars */
    {
      cursize = 1;
      if ((*ch & 0xc0) == 0xc0)		/* first multibyte octet */
	while ((ch[cursize] & 0xc0) == 0x80)
	  cursize++;			/* skip rest of octets */
      if (ch + cursize > chmax)
	break;
      chsize--;				/* char counted */
      ch += cursize;
    }
    len = (char *)ch - line;
  }
  else if (MB_CUR_MAX > 1)	/* another multibyte charset is in use */
  {
    register ssize_t cursize;
    int chsize = maxchars;
    const char *ch = line;
    size_t todo = len;
    mbstate_t ms;

    while (chsize > 0 && todo > 0 && *ch)
    {
      cursize = mbrlen(ch, todo, &ms);
      if (cursize <= 0)			/* break at invalid char */
	break;
      chsize--;
      ch += cursize;
      todo -= cursize;
    }
    len = ch - line;
  }
  else				/* 8bit encoding - just let's cut it */
    if ((int)len > maxchars)		/* may be it's already ok */
      len = maxchars;
  return len;
}


static int pattern_size (const char *pattern, const char *pe)
{
  register const char *c;
  register int s;

  c = &pattern[1];
  switch (*pattern)
  {
    case '[':
      while (*c)			/* skip rest up to ']' */
      {
	if (*c == '-') c++;		/* it's range so skip both chars */
	else if (*c == ']')		/* and -] is still allowed */
	  break;
	c++;
      }
      if (!*c++) return (-1);		/* "[..." is error */
      break;
    case '{':
      while (*c && *c != '}')		/* recursively skip up to '}' */
	if ((s = pattern_size (c, pe)) < 0)
	  return s;
	else
	  c += s;
      if (!*c++) return (-1);		/* "{..." is error */
      break;
    case '\\':
      if (!*c++) return (-1);		/* "\" is error */
    default:;				/* all other chars are one-by-one */
  }
  if (c > pe) return (-1);		/* out of bound! */
  return (c - pattern);
}

static char Wildcards[] = "[?*{";
#define wildcard(c) strchr (Wildcards, c)

static int match_it_mb (const char *p, const char *pe, const char *t, const char *te, char pp)
{
  const char *c;
  int count = 0, rc;
  register int r;
  wchar_t wc, cch;
  mbstate_t ms;

  memset(&ms, 0, sizeof(ms));	/* reset state */
  while (p < pe) {
    switch (*p) {
    case '[':
      if (t >= te)
	return (-1);
      r = pattern_size(p, pe) - 2;
      if (r < 0)
	return (-1);		/* invalid pattern */
      c = &p[1];		/* ptr for testing */
      p = &c[r];		/* new pattern end */
      r = mbrtowc(&cch, t, te - t, &ms);
      if (r < 1)
	return (-1);		/* invalid text */
      t += r;
      rc = 0;
      if (*c == '^') {
	rc = -1;		/* mark reverse matching */
	c++;
      }
      if (*c == '-') {
	if (cch == '-')		/* char matched */
	  break;
	c++;
	if (*c == ']') {	/* -] is literal at start */
	  if (cch == ']')
	    break;
	  c++;
	}
      }
      while (*c != ']') {
	r = mbrtowc(&wc, c, p - c, &ms);
	if (r < 0)
	  return (-1);		/* invalid pattern */
	if (cch == wc)
	  break;
	c += r;
	if (*c == '-') {
	  c++;
	  if (cch < wc)		/* below range */
	    continue;
	  r = mbrtowc(&wc, c, p - c, &ms);
	  if (r < 1)
	    return (-1);	/* invalid pattern */
	  if (cch <= wc)	/* in range */
	    break;
	  c += r;
	}
      }
      r = rc;
      if (*c == ']')		/* no matched chars found */
	r = -1 - rc;		/* invert matching flag */
      count++;			/* count it if matched */
      break;
    case '?':
      if (t >= te)
	return (-1);
      r = mbrtowc(&cch, t, te - t, &ms);
      if (r == 0)
	r = -1;			/* no text here */
      t += r;			/* should be consumed */
      if (pp == '*' && p[1] == '*') /* short '*?*' to '*?' */
	p++;			/* p points to '*' again */
      break;
    case '*':
      if (pp == '*') {		/* skip duplicate '*' */
	r = 0;
	break;
      }
      rc = -1;
      for (c = t; (char *)c <= te; ) {
	r = match_it_mb(&p[1], pe, c, te, '*');
	if (r > rc)
	  rc = r;
	if ((char *)c < te) {
	  r = mbrtowc(&cch, c, te - c, &ms);
	  if (r < 1)
	    return (-1);	/* invalid text */
	  c += r;
	} else
	  break;
      }
      if (rc < 0)
	return (rc);
      return (rc + count);
    case '{':
      r = pattern_size(p, pe);
      if (r < 0)
	break;			/* invalid pattern */
      c = &p[r];
      rc = -1;
      while (*p != '}') {	/* check each subpattern */
	const char *ps, *tc;
	int rt;

	p++;			/* skip '{' or ',' */
	ps = p;
	while (*p != ',' && *p != '}')
	  p++;			/* now it's on ',' or '}' */
	for (tc = t; tc <= te; ) {
	  r = match_it_mb(ps, p, t, tc, '{');
	  if (r >= 0) {		/* initial part matches */
	    rt = r;
	    r = match_it_mb(c, pe, tc, te, '}');
	    if (r >= 0) {	/* rest matches */
	      r += rt;
	      if (r > rc)	/* best matched */
		rc = r;
	    }
	  }
	  if (tc >= te)		/* cycle ended */
	    break;
	  r = mbrtowc(&wc, tc, te - tc, &ms);
	  if (r < 0)
	    return (r);		/* invalid text */
	  tc += r;
	}
      }
      if (rc < 0)
	return (rc);
      return (rc + count);
    case '\\':
      p++;			/* skip one escaped char */
    default:
      r = mbrtowc(&cch, t, te - t, &ms);
      if (r < 1)
	return (-1);		/* invalid text */
      t += r;			/* should be consumed */
      r = mbrtowc(&wc, p, pe - p, &ms);
      if (cch != wc)
	r = -1;
      else
	p += (r - 1);		/* p will be incremented below */
      count++;
    }
    if (r < 0 || t > te)
      return (-1);		/* invalid pattern above */
    pp = *p++;
  }
  if (t < te)			/* not consumed by pattern */
    return (-1);
  return (count);
}

static int match_it (const char *p, const char *pe, const char *t, const char *te, char pp)
{
  const unsigned char *c;
  int count = 0, rc;
  register int r;
  register unsigned char cch;

  while (p < pe) {
    switch (*p) {
    case '[':
      if (t >= te)
	return (-1);
      r = pattern_size(p, pe) - 2;
      if (r < 0)
	return (-1);		/* invalid pattern */
      c = &p[1];		/* ptr for testing */
      p = &c[r];		/* new pattern end */
      cch = *t++;
      r = 0;
      if (*c == '^') {
	r = -1;			/* mark reverse matching */
	c++;
      }
      if (*c == '-') {
	if (cch == '-')		/* char matched */
	  break;
	c++;
	if (*c == ']') {	/* -] is literal at start */
	  if (cch == ']')
	    break;
	  c++;
	}
      }
      while (*c != ']') {
	if (cch == *c)
	  break;
	if (c[1] == '-') {
	  if (cch > *c && cch <= c[2])
	    break;
	  c += 2;
	}
	c++;
      }
      if (*c == ']')		/* no matched chars found */
	r = -1 - r;		/* invert matching flag */
      count++;			/* count it if matched */
      break;
    case '?':
      r = 0;
      t++;			/* should be consumed */
      if (pp == '*' && p[1] == '*') /* short '*?*' to '*?' */
	p++;			/* p points to '*' again */
      break;
    case '*':
      if (pp == '*') {		/* skip duplicate '*' */
	r = 0;
	break;
      }
      rc = -1;
      for (c = t; (char *)c <= te; c++) {
	r = match_it(&p[1], pe, c, te, '*');
	if (r > rc)
	  rc = r;
      }
      if (rc < 0)
	return (rc);
      return (rc + count);
    case '{':
      r = pattern_size(p, pe);
      if (r < 0)
	break;			/* invalid pattern */
      c = &p[r];
      rc = -1;
      while (*p != '}') {	/* check each subpattern */
	const char *ps, *tc;
	int rt;

	p++;			/* skip '{' or ',' */
	ps = p;
	while (*p != ',' && *p != '}')
	  p++;			/* now it's on ',' or '}' */
	for (tc = t; tc <= te; tc++) {
	  r = match_it(ps, p, t, tc, '{');
	  if (r < 0)		/* initial part doesn't match */
	    continue;
	  rt = r;
	  r = match_it(c, pe, tc, te, '}');
	  if (r < 0)		/* rest doesn't match */
	    continue;
	  r += rt;
	  if (r > rc)		/* best matched */
	    rc = r;
	}
      }
      if (rc < 0)
	return (rc);
      return (rc + count);
    case '\\':
      p++;			/* skip one escaped char */
    default:
      r = 0;
      if (*p != *t++)
	r = -1;
      count++;
    }
    if (r < 0 || t > te)
      return (-1);		/* invalid pattern above */
    pp = *p++;
  }
  if (t < te)			/* not consumed by pattern */
    return (-1);
  return (count);
}

#define PATTERN_MAX_LEN HOSTMASKLEN

/* check for matching in shell wildcards style:
 * returns -1 if no matched, or number of not-wildcards characters matched */
int match (const char *mask, const char *text)
{
  register int cur, ptr = 0;

  if ((!text || !*text) && (!mask || !*mask))	/* empty string are equal */
    return 0;
  if (mask)
  {
    while (mask[ptr])				/* check whole pattern */
      if ((cur = pattern_size (&mask[ptr], &mask[PATTERN_MAX_LEN])) < 0)
	return cur;				/* OOPS! invalid pattern! */
      else
	ptr += cur;
  }
  if ((mask && *mask == '*' && !mask[1]) ||	/* "*" is equal to anything */
      (text && *text == '*' && !text[1]))
    return 0;
  if (!text || !mask)				/* NULL not matched to smth */
    return -1;
//  return match_it (mask, &text, &mask[ptr]);	/* do real comparison */
  if (MB_CUR_MAX > 1)
    return match_it_mb(mask, &mask[ptr], text, &text[strlen(text)], '0');
  return match_it(mask, &mask[ptr], text, &text[strlen(text)], '0');
}


#define swildcard(c) (c == '*' || c == '?' || c == '\\')

static int smatch_it_mb (const char *p, const char *pe, const char *t,
			 const char *te, char pp)
{
  const char *tc;
  int count = 0, rc;
  register int r;
  wchar_t wc, pc;
  mbstate_t ms;

  memset(&ms, 0, sizeof(ms));	/* reset the state */
  while (*p) {
    switch (*p) {
    case '?':
      if (*t == '\0')
	return (-1);
      r = mbrtowc(&wc, t, te - t, &ms);
      if (r < 1)
	return (-1);
      t += r;
      if (pp == '*' && p[1] == '*') /* short '*?*' to '*?' */
	p++;			/* p points to '*' again */
      break;
    case '*':
      if (pp == '*')		/* skip duplicate '*' */
	break;
      rc = -1;
      p++;
      for (tc = t; tc <= te; ) {
	r = smatch_it_mb(p, pe, tc, te, '*');
	if (r > rc)
	  rc = r;
	if (tc == te)
	  break;
	r = mbrtowc(&wc, tc, te - tc, &ms);
	if (r < 1)
	  return (-1);
	tc += r;
      }
      if (rc < 0)		/* rest doesn't match */
	return (rc);
      return (rc + count);
    case '\\':
      if (swildcard(p[1]))
	p++;			/* skip one escaped wildcard */
      /* else take it literally */
    default:
      r = mbrtowc(&wc, t, te - t, &ms);
      if (r < 1)
	return (-1);
      t += r;
      if (mbrtowc(&pc, p, pe - p, &ms) < 1 || pc != wc)
	return (-1);
      p += (r - 1);		/* p is incremented below */
      count++;
    }
    pp = *p++;
  }
  if (*t != '\0')
    return (-1);
  return (count);
}

static int smatch_it (const char *p, const char *t, char pp)
{
  const char *tc;
  int count = 0, rc;
  register int r;

  while (*p) {
    switch (*p) {
    case '?':
      if (*t++ == '\0')
	return (-1);
      if (pp == '*' && p[1] == '*') /* short '*?*' to '*?' */
	p++;			/* p points to '*' again */
      break;
    case '*':
      if (pp == '*')		/* skip duplicate '*' */
	break;
      rc = -1;
      for (tc = t; *tc; tc++) {
	r = smatch_it(&p[1], tc, '*');
	if (r > rc)
	  rc = r;
      }
      if (rc < 0)		/* rest doesn't match */
	return (rc);
      return (rc + count);
    case '\\':
      if (swildcard(p[1]))
	p++;			/* skip one escaped wildcard */
      /* else take it literally */
    default:
      if (*p != *t++)
	return (-1);
      count++;
    }
    pp = *p++;
  }
  if (*t != '\0')
    return (-1);
  return (count);
}

int simple_match (const char *mask, const char *text)
{
//  register int ptr;

  if ((!text || !*text) && (!mask || !*mask))	/* empty string are equal */
    return 0;
  if ((mask && *mask == '*' && !mask[1]) ||	/* "*" is equal to anything */
      (text && *text == '*' && !text[1]))
    return 0;
  if (!text || !mask)				/* NULL not matched to smth */
    return -1;
//  ptr = strlen (mask);
//  return smatch_it (mask, &text, &mask[ptr]);	/* do real comparison */
  if (MB_CUR_MAX > 1)
    return smatch_it_mb(mask, &mask[strlen(mask)], text, &text[strlen(text)], '\0');
  return smatch_it (mask, text, '\0');		/* do real comparison */
}

int Have_Wildcard (const char *str)
{
  register int i;

  for (i = 0; str[i]; i++)
    if (wildcard (str[i]))
      return i;
  return -1;
}


/* bs is max space available if text doesn't fit in linelen s
 * bs >= s if no wrapping
 * bs == 0 if wrapping enabled */
static ssize_t _try_subst (char *buf, size_t bs, const char *text, size_t s)
{
  size_t n = safe_strlen (text);

  if (!n || s == 0)			/* don't print, don't wrap */
    return -1;
  if (n > s && bs == 0)			/* wrap to next line */
    return 0;
  else if (n > s && n > bs)		/* no so much space available */
    n = bs;
  memcpy (buf, text, n);
  return n;
}

/*
 * count real chars in line and correct its size in case of invalid chars
 */
static int _count_chars (const char *line, size_t *len)
{
  if (MB_CUR_MAX > 1)			/* multibyte charset is in use */
  {
    register ssize_t cursize;
    int chars = 0;
    const char *ch = line;
    size_t todo = *len;
    mbstate_t ms;

    memset(&ms, 0, sizeof(ms));		/* reset the state! */
    while (todo > 0 && *ch)
    {
      cursize = mbrlen(ch, todo, &ms);
      if (cursize <= 0)			/* break at invalid char */
	break;
      chars++;
      ch += cursize;
      todo -= cursize;
    }
    if (todo)
      *len -= todo;
    return chars;
  }
  else					/* 8bit encoding - just return */
    return *len;
}

typedef struct {
  const char *t;	/* pointer to template */
  size_t i;		/* real chars in line */
  char *nick;
  const char *host;
  const char *lname;
  char *chan;
  uint32_t ip;
  unsigned short port;
  int idle;
  const char *message;
  char idlestr[8];
  int bold;
  int flash;
  int color;
  int ul;
  int inv;
} printl_t;

static void makeidlestr (printl_t *p)
{
  if (p->idle <= 0 || p->idlestr[0] != 0)
    return;
  /* %Mm:%Ss */
  if (p->idle < 3600)
    snprintf (p->idlestr, sizeof(p->idlestr), "%2dm:%02ds", p->idle/60,
	      p->idle%60);
  /* %kh:%Mm */
  else if (p->idle < 86400)
    snprintf (p->idlestr, sizeof(p->idlestr), "%2dh:%02dm", p->idle/3600,
	      (p->idle%3600)/60);
  /* %ed:%Hh */
  else
    snprintf (p->idlestr, sizeof(p->idlestr), "%2dd:%02dh", p->idle/86400,
	      (p->idle%86400)/3600);
}

/* returns new buffer pointer */
/* ll - line length, q - need check for '?' */
static char *_try_printl (char *buf, size_t s, printl_t *p, size_t ll, int q)
{
  char tbuf[SHORT_STRING];
  struct utsname unbuf;
  register char *c;
  const char *t = p->t;
  const char *cc, *end;

  unbuf.sysname[0] = 0;
  c = buf;				/* set to end of buffer */
  while (*t && (!q || *t != '?'))
  {					/* all colors are mIRC colors */
    if (p->i == 0 && &buf[s+7] > c)
    {
      if (p->bold)			/* recreate modes at new line */
	*c++ = '\002';			/* i is number of real chars in buff */
      if (p->flash)			/* c is ptr in buff */
	*c++ = '\006';
      if (p->ul)
	*c++ = '\037';
      if (p->inv)
	*c++ = '\026';
      if (p->color)
      {
	snprintf (c, s, "\003%d", p->color - 1);
	c = &c[strlen(c)];
      }
    }
    while (ll == 0 || p->i < ll)
    {
      ssize_t n;			/* n is number of real chars to add */
      size_t nmax;
      const char *fix;
      ssize_t nn, fw;
      static char mircsubst[] = "WkbgRrmyYGcCBMKw";

      if (!q || (end = strchr (t, '?')) == NULL)
        end = &t[strlen(t)];
      cc = strchr (t, '\n');
      if (cc && cc < end)
	end = cc;			/* now end is template for parse */
      n = end - t;
      if (ll && (size_t)n > ll - p->i)
	n = ll - p->i;			/* now n is template that fit here */
      nn = &buf[s-1] - c;		/* rest chars in buff */
      if (nn < 0)
        nn = 0;
      cc = memchr (t, '%', n);
      if (!cc)				/* next subst is over */
      {					/* try by words */
	const char *cs;

	if (end > &t[n])		/* if template doesn't fit */
	  for (cc = cs = t; *cs && cc <= &t[n]; cc = NextWord ((char *)cs))
	    cs = cc;
	else
	  cs = end;
/*	if (q && *end == '?' && cs > end)
	  cs = end;*/
	/* cs now is first char of unfitting word so skip end spaces */
	cc = cs;
	if (!q || *cc != '?')
	  while (cc > t && (*(cc-1) == ' ' || *(cc-1) == '\t')) cc--;
	/* cc now is after last fitting word */
	n = cc - t;
	if (n > nn)			/* how many chars we can put here? */
	  n = nn;
	if (n) memcpy (c, t, n);
	c += n;
	t = cs;				/* first word for next line (or NL?) */
	break;
      }
      n = cc - t;			/* chars to subst */
      if (n > nn)			/* how many chars we can put here? */
	n = nn;
      if (n) memcpy (c, t, n);
      nn -= n;
      t = cc;				/* we are on '%' now */
      p->i += n;			/* and we have line space for it */
      c += n;
      if (ll && p->i != 0)		/* nmax is max for line, 0 to wrap */
	nmax = 0;				/* wrap: drop line to ll */
      else
	nmax = nn;				/* rest of buffer */
      fix = &t[1];
      fw = 0;
      if (*fix >= '0' && *fix <= '9')	/* we have fixed field width here */
      {
	fw = (int)strtol (fix, (char **)&fix, 10);
	if (fw < nn)
	{
	  nmax = nn;		/* disable wrapping: assume field has width n */
	  nn = fw;
	}
      }
      else if (ll && (size_t)nn > ll - p->i)
	nn = ll - p->i;			/* nn is rest for line - at least 1 */
      n = 0;
      tbuf[0] = 0;
      if ((cc = strchr (mircsubst, *fix)))
      {
	p->color = ++cc - mircsubst;	/* mIRC color incremented by 1 */
	snprintf (tbuf, sizeof(tbuf), "\003%d", p->color - 1);
      }
      else switch (*fix)		/* nmax must be 0 (wrap) or nmax > nn */
      {
	case 'N':			/* the user nick */
	  n = _try_subst (c, nmax, p->nick, nn);
	  break;
	case '=':			/* my nick */
	  n = _try_subst (c, nmax, Nick, nn);
	  break;
	case '@':			/* the host name */
	  n = _try_subst (c, nmax, p->host, nn);
	  break;
	case 'L':			/* the user lname */
	  n = _try_subst (c, nmax, p->lname, nn);
	  break;
	case '#':			/* channel(s) */
	  n = _try_subst (c, nmax, p->chan, nn);
	  break;
	case '-':			/* idle string */
	  makeidlestr (p);
	  n = _try_subst (c, nmax, p->idlestr, nn);
	  break;
	case 's':
	  if (unbuf.sysname[0] == 0)
	    uname (&unbuf);
	  n = _try_subst (c, nmax, unbuf.sysname, nn);
	  break;
	case 'I':			/* IPv4 in dot notation */
	  inet_ntop (AF_INET, &p->ip, tbuf, sizeof(tbuf));
	  break;
	case 'P':			/* port number, zero is "" */
	  snprintf (tbuf, sizeof(tbuf), "%.0hu", p->port);
	  n = -1;			/* in case of zero mark as empty */
	  break;
	case 't':			/* current time */
	  n = _try_subst (c, nmax, TimeString, nn);
	  break;
	case 'n':			/* color stop */
	  p->color = 0;
	  if (nn) *c++ = '\003';
	  t = &fix[1];
	  break;
	case '^':
	  p->bold ^= 1;
	  if (nn) *c++ = '\002';
	  t = &fix[1];
	  break;
	case '_':
	  p->ul ^= 1;
	  if (nn) *c++ = '\037';
	  t = &fix[1];
	  break;
	case 'v':
	  p->inv ^= 1;
	  if (nn) *c++ = '\026';
	  t = &fix[1];
	  break;
	case 'f':
	  p->flash ^= 1;
	  if (nn) *c++ = '\006';
	  t = &fix[1];
	  break;
	case '?':
	  p->t = &fix[2];			/* skip "%?x" */
	  switch (fix[1])
	  {
	    case 'N':
	      if (p->nick && *p->nick)
		n = 1;
	      break;
	    case '@':
	      if (p->host && *p->host)
		n = 1;
	      break;
	    case 'L':
	      if (p->lname && *p->lname)
		n = 1;
	      break;
	    case '#':
	      if (p->chan && *p->chan)
		n = 1;
	      break;
	    case 'I':
	      if (p->ip)
		n = 1;
	      break;
	    case 'P':
	      if (p->port)
		n = 1;
	      break;
	    case '-':
	      if (p->idle)
		n = 1;
	      break;
	    case '*':
	      if (p->message && *p->message)
		n = 1;
	  }
	  end = &buf[s];		/* for the next _try_printl */
	  if (n)
	  {
	    c = _try_printl (c, end - c, p, ll, 1);
	    _try_printl (c, 0, p, ll, 1);
	    n = 0;
	  }
	  else
	  {
	    _try_printl (c, 0, p, ll, 1);
	    c = _try_printl (c, end - c, p, ll, 1);
	  }
	  t = p->t;
	  break;
	case '*':
	  n = _try_subst (c, nmax, p->message, nn);
	  break;
	case 'V':
	  n = _try_subst (c, nmax, PACKAGE "-" VERSION, nn);
	  break;
	case '%':			/* just a percent */
	  if (nn) *c++ = '%';
	default:
	  t = &fix[1];			/* all other are ignored */
      }
      if (*tbuf)
	n = _try_subst (c, nmax, tbuf, nn);
      if (n)
      {
	if (n > 0)			/* if something was added */
	{
	  register int chars;

	  chars = _count_chars (c, &n);
	  c += n;
	  p->i += chars;
	  n = chars;
	}
	else				/* if no space available or empty */
	  n = 0;
	for (; n < fw; n++)		/* check if fixed size */
	  *c++ = ' ';			/* fill rest with spaces */
	t = &fix[1];			/* skip command char */
      }
    }
    end = &buf[s];
    if ((!q || *t != '?') && c < end)	/* if line was wrapped */
    {
      if (p->bold)			/* reset modes at end of line */
	*c++ = '\002';
      if (p->flash && c < end)
	*c++ = '\006';
      if (p->ul && c < end)
	*c++ = '\037';
      if (p->inv && c < end)
	*c++ = '\026';
      if (p->color && c < end)
	*c++ = '\003';
      if (*t && c < end)
	*c++ = '\n';
    }
    /* terminate the line */
    if (s)
    {
      if (c == end)
	c--;
      *c = 0;
    }
    /* we are at EOL - recalculate buf and s */
    if (c > end)
      s = 0;
    else
      s -= (c - buf);
    buf = c;
    p->i = 0;
    if (*t == ' ' || *t == '\t' || *t == '\n')
      t++;				/* line wrapped so skip wrapping char */
  }
  if (q && *t == '?')			/* skip the '?' */
    t++;
  p->t = t;
  return c;
}

size_t printl (char *buf, size_t s, const char *templ, size_t strlen,
		char *nick, const char *uhost, const char *lname, char *chan,
		uint32_t ip, unsigned short port, int idle, const char *message)
{
  printl_t p;

  if (buf == NULL || s == 0) /* nothing to do */
    return 0;
  if (templ == NULL || *templ == 0) /* just terminate line if empty template */
  {
    buf[0] = 0;
    return 0;
  }
  p.t = templ;
  p.nick = nick;
  p.host = uhost;
  p.lname = lname;
  p.chan = chan;
  p.ip = htonl (ip);
  p.port = port;
  p.idle = idle;
  p.message = message;
  p.idlestr[0] = 0;
  p.i = p.bold = p.flash = p.color = p.ul = p.inv = 0;
  return (_try_printl (buf, s, &p, strlen, 0) - buf);
}

/* thanks to glibc and gcc for showing me how to optimize it */
size_t strfcpy (char *d, const char *s, size_t n)
{
  register char *s1 = d;
  register const char *s2 = s;
  register char c;

  if (n == 0)
    return 0;
  if ((--n) >= 4)
  {
    size_t n4 = n >> 2;

    do {
      if ((c = *s2) == '\0')
	goto to_return;
      *s1++ = c, s2++;
      if ((c = *s2) == '\0')
	goto to_return;
      *s1++ = c, s2++;
      if ((c = *s2) == '\0')
        goto to_return;
      *s1++ = c, s2++;
      if ((c = *s2) == '\0')
        goto to_return;
      *s1++ = c, s2++;
    } while (--n4 != 0);
  }
  n &= 3;
  if (n > 0)
  {
    if ((c = *s2) == '\0')
      goto to_return;
    *s1++ = c, s2++;
    if (n > 1)
    {
      if ((c = *s2) == '\0')
	goto to_return;
      *s1++ = c, s2++;
      if (n > 2)
      {
	if ((c = *s2) == '\0')
	  goto to_return;
	*s1++ = c, s2++;
      }
    }
  }
to_return:
  *s1 = '\0';
  return (s1 - d);
}

unsigned short make_hash (const char *s)
{
  register unsigned int hash;

  if (!s) return 0;
  hash = 0;
  while (*s)
  {
    hash += (hash << 5);		/* hash*33 */
    hash ^= *s++;			/* XOR with byte */
    hash ^= (hash >> 16);		/* XOR high and low parts */
    hash &= 0xffff;			/* leave only low part */
  }
  return hash;
}
