/*
 * Copyright (C) 2003-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is part of FoxEye's source: charset conversion layer.
 */

#include "foxeye.h"

#ifdef HAVE_ICONV

#include "conversion.h"

#include <iconv.h>
#include <errno.h>

#include "init.h"

struct conversion_t
{
  struct conversion_t *next;
  struct conversion_t *prev;
  char *charset; /* allocated */
  iconv_t cdin; /* charset --> internal, NULL if charset==internal */
  iconv_t cdout; /* internal --> charset */
  int inuse;
};

static pthread_mutex_t ConvLock = PTHREAD_MUTEX_INITIALIZER;
static struct conversion_t *Conversions = NULL; /* first is internal */

static struct conversion_t *_get_conversion (const char *charset)
{
  struct conversion_t *conv, *last = NULL;

  if (charset == NULL) /* for me assume it's internal charset */
    conv = Conversions;
  else /* scan Conversions tree */
    for (conv = Conversions; conv; conv = last->next)
    {
      last = conv;
      if (!safe_strcasecmp (conv->charset, charset))
	break;
    }
  if (conv)
    return conv;
  conv = safe_malloc (sizeof(struct conversion_t));
  conv->next = NULL;
  conv->prev = last;
  if (conv->prev)	/* it's not first */
    conv->prev->next = conv;
  else			/* for internal */
    Conversions = conv;
  conv->inuse = 0;
  conv->charset = safe_strdup (charset);
  conv->cdin = conv->cdout = (iconv_t)(-1);
  return conv;
}

/*
 * find or allocate conversion structure for given charset
 * returns pointer to found structure or NULL if:
 *   - charset isn't handled
 *   - charset is internal
 */
struct conversion_t *Get_Conversion (const char *charset)
{
  struct conversion_t *conv;
  iconv_t cd;
  int inuse, cancelstate;
  char name[64]; /* assume charset's name is at most 45 char long */

  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
  if (!Conversions)
  {
    register char *dcset;

    /* test if charset name is ok */
    if (*Charset && (cd = iconv_open (Charset, "ascii")) != (iconv_t)(-1))
    {
      iconv_close (cd);
      dcset = Charset;
    }
    else
      dcset = CHARSET_8BIT;		/* Charset doesn't exist */
    pthread_mutex_lock (&ConvLock);
    conv = _get_conversion (dcset);
    DBG("Get_Conversion: set default conv=%p", conv);
  } else
    pthread_mutex_lock (&ConvLock);
  conv = _get_conversion (charset);
  inuse = conv->inuse++;
  pthread_mutex_unlock (&ConvLock);
  DBG ("Get_Conversion: %s (conv=%p)", conv->charset, conv);
  if (conv == Conversions)
    goto nullout;
  else if (inuse || conv->cdin != (iconv_t)(-1)) /* it's already filled */
    goto done;
  /* inuse == 0 so it's newly created */
  inuse = *text_replace_char;
  if (inuse)				/* do text replace */
    snprintf (name, sizeof(name), "%s//TRANSLIT", Conversions->charset);
  else					/* do ignore unknown */
    snprintf (name, sizeof(name), "%s" TRANSLIT_IGNORE, Conversions->charset);
  if ((conv->cdin = iconv_open (name, charset)) == (iconv_t)(-1))
  {
    Free_Conversion (conv);		/* charset doesn't exist */
nullout:
    pthread_setcancelstate(cancelstate, NULL);
    return NULL;
  }
  if (inuse)				/* do text replace */
    snprintf (name, sizeof(name), "%s//TRANSLIT", charset);
  else					/* do ignore unknown */
    snprintf (name, sizeof(name), "%s" TRANSLIT_IGNORE, charset);
  conv->cdout = iconv_open (name, Conversions->charset);
  DBG ("Get_Conversion: created new conv=%p", conv);
done:
  pthread_setcancelstate(cancelstate, NULL);
  return conv;
}

/*
 * frees conversion structure if it's used nowhere else
 * returns nothing
 */
void Free_Conversion (struct conversion_t *conv)
{
  if (conv == NULL)
    return;
  pthread_mutex_lock (&ConvLock);
  if (!Conversions)
  {
    pthread_mutex_unlock (&ConvLock);
    ERROR ("Free_Conversion: called while not initialized yet!");
    return;
  }
  DBG ("Free_Conversion: %s(%d)", conv->charset, conv->inuse);
  if (conv->inuse)
    conv->inuse--;
  if (conv->inuse == 0 && conv != Conversions &&
      strcasecmp (conv->charset, CHARSET_8BIT))
  {
    int cancelstate;

    DBG("Free_Conversion: freeing conv=%p cdin=%p cdout=%p", conv, conv->cdin, conv->cdout);
    FREE (&conv->charset);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
    if (conv->cdin != (iconv_t)(-1))
      iconv_close (conv->cdin);
    if (conv->cdout != (iconv_t)(-1))
      iconv_close (conv->cdout);
    pthread_setcancelstate(cancelstate, NULL);
    if (conv->prev)
      conv->prev->next = conv->next;
    if (conv->next)
      conv->next->prev = conv->prev;
    FREE (&conv);
  }
  pthread_mutex_unlock (&ConvLock);
}

struct conversion_t *Clone_Conversion (struct conversion_t *conv)
{
  pthread_mutex_lock (&ConvLock);
  if (conv != NULL)
    conv->inuse++;
  else if (!Conversions)
    ERROR ("Clone_Conversion: called while not initialized yet!");
  pthread_mutex_unlock (&ConvLock);
  DBG ("Clone_Conversion: %s", conv ? conv->charset : "");
  return conv;
}

const char *Conversion_Charset (struct conversion_t *conv)
{
  return conv ? conv->charset : Conversions->charset;
}

/*
 * do conversion from some charset to another one via iconv descriptor cd
 * given string line with size sl will be converted to buffer buf with
 * max size sz
 * returns size of converted string
 */
static size_t _do_conversion (iconv_t cd, char **buf, size_t sz,
			      const unsigned char *line, size_t *sl)
{
  char *sbuf;
  char replace_char = *text_replace_char;
  int seq = 0;

  if (cd == (iconv_t)(-1))
  {
    *buf = (char *)line;
    if (*sl <= sz) /* input line is enough */
      sz = *sl;
    (*sl) -= sz;
    return sz;
  }
  sbuf = *buf;
  if (replace_char) while (*sl && sz) /* do text replace */
  {
    size_t last = sz;

    if (iconv (cd, (ICONV_CONST char **)&line, sl, &sbuf, &sz) != (size_t)(-1) ||
	errno != EILSEQ) /* success or unrecoverable error */
      break;
    /* replace char */
    if (seq == 0 || last != sz || *line >= 0xc0) /* some text was converted */
    {
      *sbuf++ = replace_char;
      sz--;
      seq = 1;
    }
    else if (seq == 5) /* at most 6 byte sequence with one *text_replace_char */
      seq = 0;
    else
      seq++;
    line++;
    (*sl)--;
  }					/* do ignore unknown */
  else if (iconv (cd, (ICONV_CONST char **)&line, sl, &sbuf, &sz) == (size_t)(-1))
    WARNING ("conversion error: %zu chars left unconverted", *sl); /* error */
  return (sbuf - *buf);
}

size_t Do_Conversion (struct conversion_t *conv, char **buf, size_t bufsize,
		      const char *str, size_t *len)
{
  return _do_conversion (conv ? conv->cdin : (iconv_t)(-1), buf, bufsize,
			 (const unsigned char *)str, len);
}

size_t Undo_Conversion (struct conversion_t *conv, char **buf, size_t bufsize,
			const char *str, size_t *len)
{
  return _do_conversion (conv ? conv->cdout : (iconv_t)(-1), buf, bufsize,
			 (const unsigned char *)str, len);
}

void Status_Encodings (INTERFACE *iface)
{
  struct conversion_t *conv;

  /* do all cycle with lock set since New_Request() should never lock it */
  pthread_mutex_unlock (&ConvLock);
  if ((conv = Conversions))
  {
    /* there is no reason to count Conversions->inuse since it will be 0
       after few interfaces are deleted (see dispatcher.c) */
    New_Request (iface, 0, "Conversions: internal charset %s.",
		 conv->charset);
    while ((conv = conv->next))
      New_Request (iface, 0, "Conversions: charset %s, used %d times.",
		   conv->charset, conv->inuse);
  }
  pthread_mutex_unlock (&ConvLock);
}

#endif
