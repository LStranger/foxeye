/*
 * Copyright (C) 1996-8 Michael R. Elkins <me@cs.hmc.edu>
 * Copyright (C) 1999 Thomas Roessler <roessler@guug.de>
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
 * All support functions with safeguards. :)
 */

#include "foxeye.h"
#include "init.h"

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>

static char *mem_msg = N_("Out of memory!");

void *safe_calloc (size_t nmemb, size_t size)
{
  void *p;

  if (!nmemb || !size)
    return NULL;
  if (!(p = calloc (nmemb, size)))
    bot_shutdown (mem_msg, 2);
  return p;
}

void *safe_malloc (size_t siz)
{
  void *p;

  if (siz == 0)
    return NULL;
  if ((p = (void *) malloc (siz)) == 0)
    bot_shutdown (mem_msg, 2);
  return p;
}

void safe_realloc (void **p, size_t siz)
{
  void *r;

  if (siz == 0)
  {
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
  *p = r;
}

void safe_free (void **p)
{
  if (*p)
  {
    free (*p);
    *p = NULL;
  }
}

char *safe_strdup (const char *s)
{
  char *p;
  size_t l;

  if (!s || !*s) return NULL;
  l = safe_strlen (s) + 1;
  p = (char *)safe_malloc (l);
  memcpy (p, s, l);
  return (p);
}

/* own function instead of ugly strncat() */
char *strfcat (char *dst, const char *src, size_t n)
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

/* convert all characters in the string to lowercase */
char *safe_strlower (char *dst, const char *src, size_t sz)
{
  register char *s = dst;
  register char c;

  while ((c = *src++) != 0 && sz-- > 1)
    *s++ = tolower (c);
  *s = 0;
  return dst;
}

char *rfc2812_strlower (char *dst, const char *src, size_t sz)
{
  register char *s = dst;
  register char c;

  while ((c = *src++) != 0 && sz-- > 1)
  {
    if (strchr ("[]\\~", c))
      *s = c ^ 32;
    else
      *s = tolower (c);
    s++;
  }
  *s = 0;
  return dst;
}

static int compare_stat (struct stat *osb, struct stat *nsb)
{
  if (osb->st_dev != nsb->st_dev || osb->st_ino != nsb->st_ino ||
      osb->st_rdev != nsb->st_rdev)
  {
    return -1;
  }

  return 0;
}

int safe_symlink (const char *oldpath, const char *newpath)
{
  struct stat osb, nsb;

  if(!oldpath || !newpath)
    return -1;

  if(unlink(newpath) == -1 && errno != ENOENT)
    return -1;

  if (oldpath[0] == '/')
  {
    if (symlink (oldpath, newpath) == -1)
      return -1;
  }
  else
  {
    char abs_oldpath[_POSIX_PATH_MAX];

    if ((getcwd (abs_oldpath, sizeof abs_oldpath) == NULL) ||
	(strlen (abs_oldpath) + 1 + strlen (oldpath) + 1 > sizeof abs_oldpath))
    return -1;

    strcat (abs_oldpath, "/");
    strcat (abs_oldpath, oldpath);
    if (symlink (abs_oldpath, newpath) == -1)
      return -1;
  }

  if(stat(oldpath, &osb) == -1 || stat(newpath, &nsb) == -1
     || compare_stat(&osb, &nsb) == -1)
  {
    unlink(newpath);
    return -1;
  }

  return 0;
}


int safe_open (const char *path, int flags)
{
  struct stat osb, nsb;
  int fd;

  if ((fd = open (path, flags, 0600)) < 0)
    return fd;

  /* make sure the file is not symlink */
  if (lstat (path, &osb) < 0 || fstat (fd, &nsb) < 0 ||
      compare_stat(&osb, &nsb) == -1)
  {
    close (fd);
    return (-1);
  }

  return (fd);
}

/*
 * when opening files for writing, make sure the file doesn't already exist
 * to avoid race conditions.
 */
FILE *safe_fopen (const char *path, const char *mode)
{
  if (mode[0] == 'w')
  {
    int fd;
    int flags = O_CREAT | O_EXCL;

    if (mode[1] == '+')
      flags |= O_RDWR;
    else
      flags |= O_WRONLY;

    if ((fd = safe_open (path, flags)) < 0)
      return (NULL);

    return (fdopen (fd, mode));
  }
  else
    return (fopen (path, mode));
}

/*
 * Read a line from ``fp'' into the dynamically allocated ``s'',
 * increasing ``s'' if necessary. The ending "\n" or "\r\n" is removed.
 * If a line ends with "\", this char and the linefeed is removed,
 * and the next line is read too.
 */
char *safe_read_line (char *s, size_t *size, FILE *fp, int *line)
{
  size_t offset = 0;
  char *ch;

  if (!s)
  {
    s = safe_malloc (STRING);
    *size = STRING;
  }

  FOREVER
  {
    if (fgets (s + offset, *size - offset, fp) == NULL)
    {
      safe_free ((void **) &s);
      return NULL;
    }
    if ((ch = safe_strchr (s + offset, '\n')) != NULL)
    {
      (*line)++;
      *ch = 0;
      if (ch > s && *(ch - 1) == '\r')
	*--ch = 0;
      if (ch == s || *(ch - 1) != '\\')
	return s;
      offset = ch - s - 1;
    }
    else
    {
      /* There wasn't room for the line -- increase ``s'' */
      offset = *size - 1; /* overwrite the terminating 0 */
      *size += STRING;
      safe_realloc ((void **) &s, *size);
    }
  }
}

char *
safe_substrcpy (char *dest, const char *beg, const char *end, size_t destlen)
{
  size_t len;

  len = end - beg;
  if (len > destlen - 1)
    len = destlen - 1;
  memcpy (dest, beg, len);
  dest[len] = 0;
  return dest;
}

char *safe_substrdup (const char *begin, const char *end)
{
  size_t len;
  char *p;

  len = end - begin;
  p = safe_malloc (len + 1);
  memcpy (p, begin, len);
  p[len] = 0;
  return p;
}

char *safe_strpbrk (const char *s, const char *a)
{
  return strpbrk (NONULL(s), a);
}

int safe_strcmp(const char *a, const char *b)
{
  return strcmp(NONULL(a), NONULL(b));
}

int safe_strcasecmp(const char *a, const char *b)
{
  return strcasecmp(NONULL(a), NONULL(b));
}

int safe_strncmp(const char *a, const char *b, size_t l)
{
  return strncmp(NONULL(a), NONULL(b), l);
}

int safe_strncasecmp(const char *a, const char *b, size_t l)
{
  return strncasecmp(NONULL(a), NONULL(b), l);
}

size_t safe_strlen(const char *a)
{
  return a ? strlen (a) : 0;
}

char *safe_strchr (const char *s, int c)
{
  register char *r = (char *)s;
  register char ch = c;

  if (r)
  {
    for (; *r && *r != ch; r++);
    if (*r == 0)
      r = NULL;
  }
  return r;
}

static char Wildcards[] = "~%*{?[";
#define wildcard(c) strchr (Wildcards, c)

static int match_wildcard (uchar *w, uchar c)
{
  register int i = 1;
  register uchar ec = ']';

  if (c) switch (*w)
  {
    case '~':
      if (c == ' ')
	return 1;
      break;
    case '%':
      if (c != ' ')
	return 1;
      break;
    case '*':
      return 1;
    case '{':
      ec = '}';
    case '[':
      if (w[1] == '^')
      {
	i = 0;
	w++;
      }
      do
      {
	w++;
	if (c == *w)
	  return i;
	if (*w && w[1] == '-' && w[2])
	{
	  if (c >= *w && c <= w[2])
	    return i;
	  w += 2;
	}
      } while (*w && w[1] != ec);
      if (!i)
	return 1;
      break;
    case '?':
      if (c)
	return 1;
      break;
    case '\\':
      w++;
    default:
      if (*w == c)
	return 1;
  }
  return 0;
}

static uchar *skip_wildcard (uchar *s)
{
  if (*s == '[' || *s == '{')
  {
    register uchar ec = '}';

    if (*s == '[')
      ec = ']';
    if (s[1] == '^')
      s++;
    do
    {
      s++;
      if (*s && s[1] == '-' && s[2])
	s += 2;
    } while (*s && s[1] != ec);
    if (*s)
      s++;
  }
  if (*s)
    s++;
  return s;
}

/* wildcards:
 *	~	one or more of spaces
 *	%	any number of non-spaces
 *	*	any number of any chars
 *	{a-n}	any number of characters of range a...n
 *	{^a-n}	any number of characters not of range a...n
 *	?	any character
 *	[a-n]	any character of range a...n
 *	[^a-n]	any character not of range a...n
 *	\	quote next char
 */
static int match_it (uchar *mask, uchar *text)
{
  register uchar *m, *t, *mn;
  uchar *next;
  int cur, n = -1;

  if (!*mask && !*text)			/* empty strings are equal always */
    return 0;
  /* firstly - we check for matching at all */
  while (*text && *mask && match_wildcard (mask, *text))
  {
    m = mask;
    t = text;
    next = NULL;
    /* check and skip minimum of matching wildcards */
    while (wildcard (*m) && match_wildcard (m, *t))
    {
      mn = skip_wildcard (m);
      if (*m == '~')			/* at least one space */
	t++;
      if (*m == '?' || *m == '[')	/* this is exact matched to one char */
	t++;
      else
	while (match_wildcard (m, *t) && !match_wildcard (mn, *t)) t++;
      if (!next)			/* set next for skipping */
	next = t;
      m = mn;
    }
    mn = t;				/* save pointer for calculate */
    /* check matched chars */
    while (*t && *m && !wildcard (*m))
    {
      if (*m == '\\')			/* skip quote char */
	m++;
      if (*m != *t)
        break;
      m++;
      t++;
    }
    /* m and t unmatched here or frame ends - try next frame */
    if ((cur = match_it (m, t)) >= 0)
      cur += (t - mn);			/* sum mathced nowildcards */
    if (cur > n)
      n = cur;				/* get maximum */
    /* go to next character - if exact, skip mask too, else only text++ */
    if (!next || next == text)
      text++;
    else
      text = next;
    if (*mask == '[' || *mask == '?' || !match_wildcard (mask, *text))
      mask = skip_wildcard (mask);
    if (!wildcard (*mask))
      break;
  }
  return n;
}

/* check for matching in shell wildcards style:
 * returns -1 if no matched, or number of not-wildcards characters matched */
int match (const char *mask, const char *text)
{
  if ((!text || !*text) && (!mask || !*mask))
    return 0;
  if ((mask && *mask == '*' && !mask[1]) ||
      (text && *text == '*' && !text[1]))
    return 0;
  if (!text || !mask)
    return -1;
  if (Have_Wildcard (mask) < 0)
  {
    if (strcmp (mask, text))
      return -1;
    return (strlen (mask));
  }
  return match_it ((uchar *)mask, (uchar *)text);
}

char *NextWord (const char *msg)
{
  if (msg == NULL) return (char *)msg;
  while (*msg && *msg != ' ') msg++;
  while (*msg == ' ') msg++;
  return (char *)msg;
}

char *NextWord_Unquoted (char *name, const char *line, size_t s)
{
  register char *c;
  char ch;

  if ((c = (char *)line) == NULL)
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
      *name++ = *c++;
      s--;
    }
  }
  if (s)
    *name = 0;
  while (*c == ' ') c++;
  return c;
}

void StrTrim (char *cmd)
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
      int nn;
      static char mircsubst[] = "WkbgrymRYGcCBMKw";

      if (!q || (end = strchr (t, '?')) == NULL)
        end = &t[strlen(t)];
      cc = strchr (t, '\n');
      if (cc && cc < end)
	end = cc;			/* now end is template for parse */
      n = end - t;
      if (ll && n > ll - p->i)
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
      else if (ll && nn > ll - p->i)
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
//fprintf(stderr,"%s[%u]:nick=%s:uhost=%s:lname=%s:chan=%s:ip=%u:port=%hu:msg=%s\n",templ,strlen,nick,uhost,lname,chan,ip,port,message);
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

const char *expand_path (char *buf, const char *str, size_t s)
{
  if (safe_strncmp (str, "~/", 2))
    return str;
  snprintf (buf, s, "%s/%s", getenv ("HOME"), &str[2]);
  return buf;
}
