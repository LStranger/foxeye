/*
 * Copyright (C) 2003-2006  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * charset conversion definitions
 */

#include "foxeye.h"

#ifdef HAVE_ICONV

#include "conversion.h"

#include <iconv.h>
#include <pthread.h>
#include <errno.h>

#include "init.h"

struct conversion_t
{
  struct conversion_t *next;
  struct conversion_t *prev;
  int inuse;
  char *charset; /* allocated */
  iconv_t cdin; /* charset --> internal, NULL if charset==internal */
  iconv_t cdout; /* internal --> charset */
};

static pthread_mutex_t ConvLock = PTHREAD_MUTEX_INITIALIZER;
static conversion_t *Conversions = NULL; /* first is internal */

static conversion_t *_get_conversion (const char *charset)
{
  conversion_t *conv;

  if (charset == NULL) /* for me assume it's internal charset */
    conv = Conversions;
  else /* scan Conversions tree */
    for (conv = Conversions; conv; conv = conv->next)
      if (!strcasecmp (conv->charset, charset))
	break;
  if (conv)
    return conv;
  conv = safe_malloc (sizeof(conversion_t));
  conv->next = Conversions;
  if (conv->next)
    conv->next->prev = conv;
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
conversion_t *Get_Conversion (const char *charset)
{
  conversion_t *conv;
  iconv_t cd;
  int inuse;
  char name[64]; /* assume charset's name is at most 45 char long */

  pthread_mutex_lock (&ConvLock);
  if (!Conversions)
  {
    /* test if charset name is ok */
    if (*Charset && (cd = iconv_open (Charset, "ascii")) != (iconv_t)(-1))
    {
      iconv_close (cd);
      _get_conversion (Charset);
    }
    else
      _get_conversion (CHARSET_8BIT);	/* Charset doesn't exist */
  }
  conv = _get_conversion (charset);
  inuse = conv->inuse++;
  pthread_mutex_unlock (&ConvLock);
  if (conv == Conversions)
    return NULL;
  else if (inuse)
    return conv;
  /* inuse == 0 so it's newly created */
  inuse = *text_replace_char;
  if (inuse)				/* do text replace */
    snprintf (name, sizeof(name), "%s//TRANSLIT", Conversions->charset);
  else					/* do ignore unknown */
    snprintf (name, sizeof(name), "%s//IGNORE//TRANSLIT", Conversions->charset);
  if ((conv->cdin = iconv_open (name, charset)) == (iconv_t)(-1))
  {
    Free_Conversion (conv);		/* charset doesn't exist */
    return NULL;
  }
  if (inuse)				/* do text replace */
    snprintf (name, sizeof(name), "%s//TRANSLIT", charset);
  else					/* do ignore unknown */
    snprintf (name, sizeof(name), "%s//IGNORE//TRANSLIT", charset);
  conv->cdout = iconv_open (name, Conversions->charset);
  return conv;
}

/*
 * frees conversion structure if it's used nowhere else
 * returns nothing
 */
void Free_Conversion (conversion_t *conv)
{
  if (conv == NULL)
    return;
  pthread_mutex_lock (&ConvLock);
  if (conv->inuse)
    conv->inuse--;
  if (conv->inuse == 0 && conv != Conversions &&
      strcasecmp (conv->charset, CHARSET_8BIT))
  {
    FREE (&conv->charset);
    if (conv->cdin != (iconv_t)(-1))
      iconv_close (conv->cdin);
    if (conv->cdout != (iconv_t)(-1))
      iconv_close (conv->cdout);
    if (conv->prev)
      conv->prev->next = conv->next;
    if (conv->next)
      conv->next->prev = conv->prev;
    FREE (&conv);
  }
  pthread_mutex_unlock (&ConvLock);
}

/*
 * do conversion from some charset to another one via iconv descriptor cd
 * given string line with size sl will be converted to buffer buf with
 * max size sz
 * returns size of converted string
 */
static size_t _do_conversion (iconv_t cd, char **buf, size_t sz,
			      const unsigned char *line, size_t sl)
{
  char *sbuf;
  char replace_char = *text_replace_char;
  int seq = 0;

  if (cd == (iconv_t)(-1))
  {
    *buf = (char *)line;
    if (sl > sz) /* input line is too long? */
      return sz;
    return sl;
  }
  sbuf = *buf;
  if (replace_char) while (sl && sz) /* do text replace */
  {
    size_t last = sz;

    if (iconv (cd, (ICONV_CONST char **)&line, &sl, &sbuf, &sz) != (size_t)(-1) ||
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
    sl--;
  }					/* do ignore unknown */
  else if (iconv (cd, (ICONV_CONST char **)&line, &sl, &sbuf, &sz) == (size_t)(-1))
    WARNING ("conversion error: %lu chars left unconverted", sz); /* error */
  return (sbuf - *buf);
}

size_t Do_Conversion (conversion_t *conv, char **buf, size_t bufsize,
		      const char *str, size_t len)
{
  return _do_conversion (conv ? conv->cdin : (iconv_t)(-1), buf, bufsize,
			 (const unsigned char *)str, len);
}

size_t Undo_Conversion (conversion_t *conv, char **buf, size_t bufsize,
			const char *str, size_t len)
{
  return _do_conversion (conv ? conv->cdout : (iconv_t)(-1), buf, bufsize,
			 (const unsigned char *)str, len);
}

#endif

#if 0

/* for internal use only, see macros below */
size_t conv_do_conv(iconv_t, const unsigned char *, size_t, unsigned char **, size_t);

/* public functions */
conversion_t *conv_get_conversion(const char *);
void conv_free_conversion(conversion_t *);
conversion_t *conv_set_internal(conversion_t **old, const char *);
#define conv_inherit(parent,new) new=parent, parent->inuse++
#define conv_charset(conv) conv->charset
#define conv_do_in(conv,in,insize,out,outsize) conv_do_conv(conv->cdin,in,insize,out,outsize)
#define conv_do_out(conv,in,insize,out,outsize) conv_do_conv(conv->cdout,in,insize,out,outsize)

/* helpers for transcoding fields to new internal codepage from old one (conv)
 * note: new codepage must be different from current!
 * note2: buff size for conv_transcode() must not be less of field size! */
#define conv_transcode(conv,field,buff) do { unsigned char *c=buff;\
					    size_t sz=conv_do_conv(conv->cdin,field,strlen(field),&c,sizeof(field)-1);\
					    memcpy(field,buff,sz);\
					    field[sz]=0;} while(0)
#define conv_transcode_realloc(conv,field,buff) do { unsigned char *c=buff;\
						    size_t sz=conv_do_conv(conv->cdin,field,strlen(field),&c,sizeof(buff));\
						    MyFree(field);\
						    field=MyMalloc(sz+1);\
						    memcpy(field,buff,sz);\
						    field[sz]=0;} while(0)

void conv_report(aClient *, char *);

/*
 * sends list of all charsets and use of it, including listen ports
 * it's answer for /stats e command
*/
void conv_report(aClient *sptr, char *to)
{
  conversion_t *conv;

  if (!internal)
    return; /* it's impossible, I think! --LoSt */
  sendto_one(sptr, ":%s %d %s :Internal charset: %s",
	     ME, RPL_STATSDEBUG, to, internal->charset);
  for (conv = Conversions; conv; conv = conv->next)
    sendto_one(sptr, ":%s %d %s :Charset %s: %d",
	       ME, RPL_STATSDEBUG, to, conv->charset, conv->inuse);
}

/*
 * converts null-terminated string src to upper case string
 * output buffer dst with size ds must be enough for null-terminated string
 * else string will be truncated
 * returns length of output null-terminated string (with null char)
 * if dst == NULL or ds == 0 then returns 0
*/
size_t rfcstrtoupper(char *dst, char *src, size_t ds)
{
    size_t sout = 0, ss;

    if (dst == NULL || ds == 0)
	return 0;
    ds--;
    if (src && *src)
    {
	if (Force8bit) /* if string needs conversion to 8bit charset */
	{
	    conversion_t *conv;
	    size_t processed, rest;
	    char *ch;
	    char buf[100]; /* hope it's enough for one pass ;) */

	    ss = strlen(src);
	    conv = conv_get_conversion(CHARSET_8BIT); /* it must be already created --LoSt */
	    while (ss && ds)
	    {
		ch = buf;
		rest = sizeof(buf);
		/* use iconv() since conv_* doesn't do that we want */
		iconv(conv->cdout, (const char **)&src, &ss, &ch, &rest);
		processed = ch - buf;
		for (ch = buf; ch < &buf[processed]; ch++)
		{
		    if (*ch >= 0x7b && *ch <= 0x7d) /* RFC2812 */
			*ch = (*ch & ~0x20);
		    else if (*ch == 0x5e)
			*ch = 0x7e;
		    else
			*ch = toupper(*(unsigned char *)ch);
		}
		rest = ds;
		ch = buf;
		iconv(conv->cdin, (const char **)&ch, &processed, &dst, &ds);
		sout += (rest - ds);
		/* there still may be unconvertable chars in buffer! */
		if (rest == ds)
		    break;
	    }
	    conv_free_conversion(conv);
	}
	else
#ifdef IRCD_CHANGE_LOCALE
	if (UseUnicode && MB_CUR_MAX > 1) /* if multibyte encoding */
	{
	    wchar_t wc;
	    int len;
	    register char *ch;
	    char c[MB_LEN_MAX];

	    for (ch = (unsigned char *)src, ss = strlen(ch); *ch; )
	    {
		len = mbtowc(&wc, ch, ss);
		if (len < 1)
		{
		    ss--;
		    if ((--ds) == 0)
			break; /* no room for it? */
		    *dst++ = *ch++;
		    sout++;
		    continue;
		}
		ss -= len;
		ch += len;
		if (wc >= 0x7b && wc <= 0x7d) /* RFC2812 */
		    wc &= ~0x20;
		else if (wc == 0x5e)
		    wc = 0x7e;
		else
		    wc = toupper(wc);
		len = wctomb(c, wc); /* first get the size of lowercase mbchar */
		if (len < 1)
		    continue; /* tolower() returned unknown char? ignore it */
		if (len >= ds)
		    break; /* oops, out of output size! */
		memcpy(dst, c, len); /* really convert it */
		ds -= len; /* it's at least 1 now */
		dst += len;
		sout += len;
	    }
	}
	else
#endif
	{ /* string in internal single-byte encoding the same as locale */
	    register char ch;

	    for (ch = *src++; ch && ds; ch = *src++, sout++, ds--)
	    {
		if (ch >= 0x7b && ch <= 0x7d) /* RFC2812 */
		    *dst++ = (ch & ~0x20);
		else if (ch == 0x5e)
		    *dst++ = 0x7e;
		else
		    *dst++ = toupper((unsigned char)ch);
	    }
	}
    }
    *dst = 0;
    return (sout + 1);
}

size_t unistrcut (char *line, size_t len, size_t maxchars)
{
  if (len > maxchars)		/* may be it's already ok */
  {
#if !defined(CLIENT_COMPILE) && defined(RUSNET_IRCD)
    if (UseUnicode > 0)		/* let's count chars - works for utf* only!!! */
    {
      register size_t chsize = 0;
      register unsigned char *ch = (unsigned char *)line;
      register unsigned char *chmax = &line[len];

      while (chsize < maxchars && ch < chmax && *ch) /* go for max chars */
      {
	if ((*ch++ & 0xc0) == 0xc0)		/* first multibyte octet */
	  while ((*ch & 0xc0) == 0x80 && ch < chmax)
	    ch++;				/* skip rest of octets */
	chsize++;				/* char counted */
      }
      len = (char *)ch - line;
    }
    else			/* 8bit encoding - just let's cut it */
#endif
      len = maxchars;
  }
  if (line && line[len])
    line[len] = '\0';
  return len;
}

#endif /* 0 */
