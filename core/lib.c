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
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * This file is part of FoxEye's source: common functions library.
 */

#include "foxeye.h"
#include "init.h"

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <wchar.h>
#include <locale.h>

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
  DBG ("safe_calloc(%u*%u)=0x%08x", nmemb, size, (int)p);
  return p;
}

void *safe_malloc (size_t siz)
{
  void *p;

  if (siz == 0)
    return NULL;
  if ((p = (void *) malloc (siz)) == 0)
    bot_shutdown (mem_msg, 2);
  DBG ("safe_malloc(%u)=0x%08x", siz, (int)p);
  return p;
}

void safe_realloc (void **p, size_t siz)
{
  void *r;

  if (siz == 0)
  {
    DBG ("safe_realloc(0x%08x,0)", (int)*p);
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
  DBG ("safe_realloc(0x%08x,%u)=0x%08x", (int)*p, siz, (int)r);
  *p = r;
}

void safe_free (void **p)
{
  if (*p)
  {
    DBG ("safe_free(0x%08x)", (int)*p);
    free (*p);
    *p = NULL;
  }
}


/*
 * converts null-terminated string src to upper case string
 * output buffer dst with size ds must be enough for null-terminated string
 * else string will be truncated
 * returns length of output null-terminated string (with null char)
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
    // TODO: make support for broken systems - recode in 8 bit locale
    if (MB_CUR_MAX > 1) /* if multibyte encoding */
    {
      wchar_t wc;
      size_t len;
      register const char *ch;
      mbstate_t ms;
      char c[MB_LEN_MAX];

      for (ch = src, ss = strlen(ch); *ch && ds; )
      {
	len = mbrtowc(&wc, ch, ss, &ms);
	if (len < 1) /* unrecognized char! TODO: debug warning on it? */
	{
	  ss--;
	  *dst++ = *ch++; /* OK, we just copy it, is it the best way? */
	  sout++;
	  ds--;
	  continue;
	}
	ss -= len; /* advance pointer in sourse string */
	ch += len;
	wc = tolower(wc);
	len = wcrtomb(c, wc, &ms); /* first get the size of lowercase mbchar */
	if (len < 1)
	  continue; /* tolower() returned unknown char? ignore it */
	if (len > ds)
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
  return (sout + 1);
}

static bool _charset_is_utf = FALSE;

void foxeye_setlocale (void)
{
  char new_locale[SHORT_STRING];

  // TODO: make support for broken systems - set to 8 bit locales
  snprintf (new_locale, sizeof(new_locale), "%s.%s", locale, Charset);
  DBG ("trying set locale to %s", new_locale);
  if (setlocale (LC_ALL, new_locale) == NULL)
  {
    _charset_is_utf = FALSE;
    snprintf (new_locale, sizeof(new_locale), "%s.%s", locale, CHARSET_8BIT);
    if (setlocale (LC_ALL, new_locale) == NULL)
    {
      setlocale (LC_ALL, "");
      ERROR ("init: failed to set locale to %s, reverted to default!", new_locale);
    }
  }
  else if (!strncasecmp (Charset, "utf", 3))
    _charset_is_utf = TRUE;
  else
    _charset_is_utf = FALSE;
#ifdef ENABLE_NLS
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif
}

/*
 * truncate null-terminated string in line to contain not more than:
 *  - len bytes (including termination byte)
 *  - maxchars characters (without null char)
 * returns size of truncated string in bytes without null char
 */
size_t unistrcut (char *line, size_t len, int maxchars)
{
  len--;			/* preserve 1 byte for '\0' */
  if (_charset_is_utf == TRUE)	/* let's count chars - works for utf* only */
  {
    register int chsize = 0;
    register unsigned char *ch = (unsigned char *)line;
    register unsigned char *chmax = &line[len];

    while (chsize < maxchars && ch < chmax && *ch) /* go for max chars */
    {
      if ((*ch++ & 0xc0) == 0xc0)	/* first multibyte octet */
	while ((*ch & 0xc0) == 0x80 && ch < chmax)
	  ch++;				/* skip rest of octets */
      chsize++;				/* char counted */
    }
    len = (char *)ch - line;
  }
  // TODO: make support for broken systems - recode in 8 bit locale
  else if (MB_CUR_MAX > 1)	/* another multibyte charset is in use */
  {
    register size_t cursize;
    register int chsize = 0;
    register char *ch = line;
    char *chmax = &line[len];
    mbstate_t ms;

    while (chsize < maxchars && ch < chmax)
    {
      cursize = mbrlen(ch, chmax - ch, &ms);
      if (cursize <= 0)			/* break at invalid char */
	break;
      chsize++;
      ch += cursize;
    }
    len = ch - line;
  }
  else				/* 8bit encoding - just let's cut it */
    if ((int)len > maxchars)		/* may be it's already ok */
      len = maxchars;
  if (line && line[len])
    line[len] = '\0';
  return len;
}


static int pattern_size (const char *pattern)
{
  register const char *c;
  register int s;

  c = &pattern[1];
  switch (*pattern)
  {
    case '[':
      if (*c == '^') c++;		/* it may be first */
      if (*c == ']') c++;		/* "[]...]" is allowed too */
      if (*c == '-') c++;		/* '-' may be first literal */
      while (*c && *c != ']')		/* skip rest up to ']' */
      {
        if (*c == '-') c++;		/* it's range so skip both chars */
	if (*c) c++;
      }
      if (!*c++) return (-1);		/* "[..." is error */
      break;
    case '{':
      while (*c && *c != '}')		/* recursively skip up to '}' */
	if ((s = pattern_size (c)) < 0)
	  return s;
	else
	  c += s;
      if (!*c++) return (-1);		/* "{..." is error */
      break;
    case '\\':
      if (!*c++) return (-1);		/* "\" is error */
    default:;				/* all other chars are one-by-one */
  }
  return (c - pattern);
}

static char Wildcards[] = "[?*{";
#define wildcard(c) strchr (Wildcards, c)

/* it does literal+[pattern+rest(match_it)...] */
static int match_it (const char *mask, const char **text, const char *pe)
{
  register const uchar *m;
  const char *t, *tc, *te;		/* current char */
  const uchar *sc, *se;			/* subpattern current/end */
  int cur, x, n;

  /* starts from literal? check it and set x as match! */
  x = 0;
  t = *text;
  while (*t && !wildcard (*mask) && mask < pe)
  {
    if (*mask == '\\')			/* skip quote char */
      mask++;
    if (*mask != *t)			/* char isn't equal */
      break;
    mask++;
    t++;
    x++;
  }
  if (mask >= pe)			/* really it cannot be mask>pe */
  {
    if (!*pe && *t)			/* end of pattern is reached but text */
      return (-1);
    if (x)
      *text = t;
    return x;				/* all pattern is consumed */
  }
  if (!wildcard (*mask))		/* it's not matched */
    return (-1);
  sc = mask;				/* set this wildcard pattern ptrs */
  se = sc + pattern_size (sc);
  n = (-1);
  te = NULL;				/* to avoid compiler warning */
  while (sc < se)			/* cyclic check one wildcard pattern */
  {
    switch (*mask)
    {
      case '[':
	if (*t)
	{
	  register uchar c = *t;

	  m = mask;
	  if (m[1] == '^')
	  {
	    cur = 1;				/* mark "reverse match" */
	    m++;
	  }
	  else
	    cur = 0;
	  if (m[1] == ']' && c != ']')		/* it may be []...] */
	    m++;				/* it may be []-...] too */
	  sc = se - 1;
	  while (++m < sc)
	  {
	    if (*m == c)			/* matched exactly */
	      break;
	    else if (m[1] == '-')		/* '-' at begin is literal */
	    {
	      if (c > *m && c <= m[2])		/* matched range */
		break;
	      m += 2;
	    }
	  }
	  if ((!cur && m < sc) || (cur && m >= sc)) /* it's matched */
	    tc = t + 1, cur = match_it (se, &tc, pe); /* check rest */
	  else					/* it's not matched */
	    cur = (-1);
	}
	else					/* must be at least one char */
	  cur = (-1);
	sc = se;				/* end of pattern, of course */
	break;
      case '?':
	if (*t)					/* check rest of text */
	  tc = t + 1, cur = match_it (se, &tc, pe);
	else					/* must be at least one char */
	  cur = (-1);
	sc = se;
	break;
      case '*':
	if ((char *)se == pe)			/* it's last char of pattern */
	  tc = (t += strlen(t)), cur = 0;	/* it will be consumed all */
	else if (!*t)
	  cur = (-1);
        else while (*t && (tc = t) && (cur = match_it (se, &tc, pe)) < 0)
	  t++;					/* find matched to rest */
	if (!*t || cur < 0)			/* cannot do match anymore */
	  sc = se;
	else					/* get ready for next try */
	  t++;					/* (next char is matched '*') */
	break;
      default: /* '{' */
	m = ++sc;				/* skip '{' or ',' in pattern */
	while (*sc != ',' && sc < (se - 1))
	  sc += pattern_size (sc);		/* get end of subpattern */
	tc = t;					/* prepare start pointer */
	if (*sc == '}')				/* end of subpatterns reached */
	  cur = (-1);
	else if ((cur = match_it (m, &tc, sc)) >= 0) /* ok, it's matched */
	  cur = match_it (se, &tc, pe);		/* it's real match value */
    }
    if (cur > n && (*pe || !*tc))		/* matched to part or whole */
    {
      n = cur;					/* set max matched counter */
      te = tc;					/* and advance text ptr */
    }
  }
  if (n < 0)					/* wildcard pattern not matched */
    return (-1);
  *text = te;
  return (x + n);
}

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
      if ((cur = pattern_size (&mask[ptr])) < 0)
	return cur;				/* OOPS! invalid pattern! */
      else
	ptr += cur;
  }
  if ((mask && *mask == '*' && !mask[1]) ||	/* "*" is equal to anything */
      (text && *text == '*' && !text[1]))
    return 0;
  if (!text || !mask)				/* NULL not matched to smth */
    return -1;
  return match_it (mask, &text, &mask[ptr]);	/* do real comparison */
}


#define swildcard(c) (c == '*' || c == '?')

static int smatch_it (const char *mask, const char **text, const char *pe)
{
  const char *t, *tc, *te;		/* current char */
  const uchar *sc, *se;			/* subpattern current/end */
  int cur, x, n;

  /* starts from literal? check it and set x as match! */
  x = 0;
  t = *text;
  while (*t && !swildcard (*mask) && mask < pe)
  {
    if (*mask != *t)			/* char isn't equal */
      break;
    mask++;
    t++;
    x++;
  }
  if (mask >= pe)			/* really it cannot be mask>pe */
  {
    if (!*pe && *t)			/* end of pattern is reached but text */
      return (-1);
    if (x)
      *text = t;
    return x;				/* all pattern is consumed */
  }
  if (!swildcard (*mask))		/* it's not matched */
    return (-1);
  sc = mask;				/* set this wildcard pattern ptrs */
  se = sc + 1;
  n = (-1);
  te = NULL;				/* to avoid compiler warning */
  while (sc < se)			/* cyclic check one wildcard pattern */
  {
    switch (*mask)
    {
      case '?':
	if (*t)					/* check rest of text */
	  tc = t + 1, cur = smatch_it (se, &tc, pe);
	else					/* must be at least one char */
	  cur = (-1);
	sc = se;
	break;
      default: /* '*' */
	if ((char *)se == pe)			/* it's last char of pattern */
	  tc = (t += strlen(t)), cur = 0;	/* it will be consumed all */
	else if (!*t)
	  cur = (-1);
        else while (*t && (tc = t) && (cur = smatch_it (se, &tc, pe)) < 0)
	  t++;					/* find matched to rest */
	if (!*t || cur < 0)			/* cannot do match anymore */
	  sc = se;
	else					/* get ready for next try */
	  t++;					/* (next char is matched '*') */
    }
    if (cur > n && (*pe || !*tc))		/* matched to part or whole */
    {
      n = cur;					/* set max matched counter */
      te = tc;					/* and advance text ptr */
    }
  }
  if (n < 0)					/* wildcard pattern not matched */
    return (-1);
  *text = te;
  return (x + n);
}

int simple_match (const char *mask, const char *text)
{
  register int ptr;

  if ((!text || !*text) && (!mask || !*mask))	/* empty string are equal */
    return 0;
  if ((mask && *mask == '*' && !mask[1]) ||	/* "*" is equal to anything */
      (text && *text == '*' && !text[1]))
    return 0;
  if (!text || !mask)				/* NULL not matched to smth */
    return -1;
  ptr = strlen (mask);
  return smatch_it (mask, &text, &mask[ptr]);	/* do real comparison */
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
 * bs >= s or bs == 0 if wrapping enabled */
static size_t _try_subst (char *buf, size_t bs, const char *text, size_t s)
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

typedef struct {
  char *t;		/* pointer to template */
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
  char *t = p->t;
  char *cc, *end;

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
      char *fix;
      ssize_t nn;
      static char mircsubst[] = "WkbgrymRYGcCBMKw";

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
	char *cs;

	if (end > &t[n])		/* if template doesn't fit */
	  for (cc = cs = t; *cs && cc <= &t[n]; cc = NextWord (cs)) cs = cc;
	else
	  cs = end;
/*	if (q && *end == '?' && cs > end)
	  cs = end;*/
	/* cs now is first char of unfitting word so skip end spaces */
	for (cc = cs; cc > t && (*(cc-1) == ' ' || *(cc-1) == '\t');) cc--;
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
      if (p->i == 0)			/* nmax is max for line, 0 to wrap */
	nmax = 0;				/* wrap: drop line to ll */
      else
	nmax = nn;				/* rest of buffer */
      fix = &t[1];
      if (*fix >= '0' && *fix <= '9')	/* we have fixed field width here */
      {
	n = (int)strtol (fix, &fix, 10);
	if (n < nn)
	{
	  nmax = nn;		/* disable wrapping: assume field has width n */
	  nn = n;
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
	case 'I':
	  snprintf (tbuf, sizeof(tbuf), "%lu", (unsigned long)p->ip);
	  break;
	case 'P':
	  snprintf (tbuf, sizeof(tbuf), "%hu", p->port);
	  break;
	case 't':			/* current time */
	  n = _try_subst (c, nmax, &DateString[7], nn);
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
	  c += n;
	  p->i += n;
	}
	else				/* if no space available or empty */
	  n = 0;
	if (fix > &t[1])		/* check if fixed size */
	  for (; n < nn; n++)
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

void printl (char *buf, size_t s, char *templ, size_t strlen,
		char *nick, const char *uhost, const char *lname, char *chan,
		uint32_t ip, unsigned short port, int idle, const char *message)
{
  printl_t p;

  if (templ == NULL || buf == NULL || s == 0)
    return;
  if (*templ == 0)	/* just terminate line if empty template */
  {
    buf[0] = 0;
    return;
  }
  p.t = templ;
  p.nick = nick;
  p.host = uhost;
  p.lname = lname;
  p.chan = chan;
  p.ip = ip;
  p.port = port;
  p.idle = idle;
  p.message = message;
  p.idlestr[0] = 0;
  p.i = p.bold = p.flash = p.color = p.ul = p.inv = 0;
  _try_printl (buf, s, &p, strlen, 0);
}

/* thanks to glibc and gcc for showing me how to optimize it */
char *strfcpy (char *s1, const char *s2, size_t n)
{
  char *s = s1;

  if (n == 0)
    return NULL;
  if ((--n) >= 4)
  {
    size_t n4 = n >> 2;

    do {
      if ((s1[0] = s2[0]) == '\0')
	return s;
      if ((s1[1] = s2[1]) == '\0')
	return s;
      if ((s1[2] = s2[2]) == '\0')
        return s;
      if ((s1[3] = s2[3]) == '\0')
        return s;
      s1 += 4;
      s2 += 4;
    } while (--n4 != 0);
  }
  n &= 3;
  if (n > 0)
  {
    if ((s1[0] = s2[0]) == '\0')
      return s;
    if (n > 1)
    {
      if ((s1[1] = s2[1]) == '\0')
	return s;
      if (n > 2 && (s1[2] = s2[2]) == '\0')
	return s;
    }
  }
  s1[n] = '\0';
  return s;
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
