/*
 * Copyright (C) 2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye 'ziplink' module.
 */

#include "foxeye.h"

#ifdef HAVE_ZLIB
#include "zlib.h"

#include "modules.h"
#include "init.h"
#include "socket.h"
#include "direct.h"

struct zipbuff {
  z_stream z;
  size_t bufptr, inbuf;
  char buf[ZIPBUFSIZE];
};

struct connchain_buffer {
  struct peer_t *peer;
  struct connchain_i *saved_chain;
  struct connchain_buffer *next;
  ssize_t error;
  struct zipbuff in, out;
};

/* global list of buffers, need it in case of module termination */
struct connchain_buffer *zipbuflist = NULL;

static void _freezipbuff(struct connchain_buffer **buf)
{
  struct connchain_buffer **zb;

  for (zb = &zipbuflist; *zb; zb = &(*zb)->next)
    if (*zb == *buf)
      break;
  if (*zb != NULL)
    *zb = (*buf)->next;
  else
    ERROR("ziplink: cannot find buffer %p in list to free it!", *buf);
  DBG("ziplink: freeing buffer %p", *buf);
  FREE(buf);
}

static voidpf _z_alloc(voidpf opaque, uInt items, uInt size)
{
  return safe_calloc(items, size); /* FIXME: isn't malloc better here? */
}

static void _z_free(voidpf opaque, voidpf address)
{
  safe_free(&address);
}

static void _z_check_saved_buffer(idx_t id, struct connchain_buffer *buf)
{
  ssize_t i, o;

  /* check if there is new data to pull from buffers into buf->in.buf */
  if (buf->in.inbuf < sizeof(buf->in.buf))
    i = Connchain_Get(&buf->saved_chain, -1, &buf->in.buf[buf->in.inbuf],
		      (sizeof(buf->in.buf) - buf->in.inbuf));
  else
    i = 0;
  if (i > 0) {
    buf->in.inbuf += i;
    dprint(6, "ziplink: found compressed data: size=%zd", i);
  }
  /* check if there is old data left to push from buffers into socket */
  o = 0;
  o = Connchain_Put(&buf->saved_chain, id, NULL, &o);
  /* kill chain when done */
  if (i < 0 && o < 0 && Connchain_Get(&buf->saved_chain, id, NULL, 0))
    buf->saved_chain = NULL;
}

/* send into saved_chain while in early state and reject data
   kill saved chain as soon it's done */
static ssize_t _ccfilter_Z_send(struct connchain_i **ch, idx_t id, const char *str,
				size_t *sz, struct connchain_buffer **b)
{
  struct connchain_buffer *buf = *b;
  size_t so, sp;
  ssize_t i;

  if (buf == NULL)		/* terminated */
    return (E_NOSOCKET);
  if (buf->saved_chain != NULL) { /* not ready yet, try to push saved buffers */
    _z_check_saved_buffer(id, buf);
    if (buf->saved_chain != NULL)
      return (0);
  }
  if (buf->out.inbuf != 0) {	/* trying to push buffer now */
    so = buf->out.inbuf - buf->out.bufptr;
    i = Connchain_Put (ch, id, &buf->out.buf[buf->out.bufptr], &so);
    if (i < 0)
      return i;
    if (i > 0)
      dprint(6, "ziplink: sent compressed data, size=%zd", i);
    if (so == 0)		/* done */
      buf->out.bufptr = buf->out.inbuf = 0;
    else
      buf->out.bufptr += i;
  }
  if (str == NULL) {		/* asked to flush, we not call deflate here! */
    if (buf->out.inbuf)
      return (0);
    return Connchain_Put (ch, id, str, sz); /* ask next link to flush then */
  }
  if (*sz == 0)			{ /* a test */
    if (buf->out.inbuf >= (sizeof(buf->out.buf) - 64)) /* reserve 64 bytes */
      return (0);
    return Connchain_Put (ch, id, str, sz); /* bounce test to next link */
  }
  if (buf->out.inbuf >= (sizeof(buf->out.buf) - 16))
    return (0);			/* not ready now */
  buf->out.z.next_out = &buf->out.buf[buf->out.inbuf];
  buf->out.z.avail_out = sizeof(buf->out.buf) - buf->out.inbuf;
  buf->out.z.next_in = (char *)str;
  buf->out.z.avail_in = *sz;
  i = deflate(&buf->out.z, Z_PARTIAL_FLUSH); /* compress input into buffer */
  if (i == Z_OK) {
    buf->out.inbuf = sizeof(buf->out.buf) - buf->out.z.avail_out;
    so = *sz - buf->out.z.avail_in;
    *sz = buf->out.z.avail_in;
    dprint(6, "ziplink: compression success on [%-*.*s]", (int)so, (int)so, str);
  } else
    so = E_NOSOCKET;		/* compression error */
  if (buf->out.inbuf != 0) {	/* trying to push buffer again */
    sp = buf->out.inbuf - buf->out.bufptr;
    i = Connchain_Put (ch, id, &buf->out.buf[buf->out.bufptr], &sp);
    if (i < 0)
      return i;
    if (i > 0)
      dprint(6, "ziplink: sent compressed data, size=%zd", i);
    if (sp == 0)		/* done */
      buf->out.bufptr = buf->out.inbuf = 0;
    else
      buf->out.bufptr += i;
  }
  return (so);
}

/* termination includes saved chain if in early state */
static ssize_t _ccfilter_Z_recv(struct connchain_i **ch, idx_t id, char *str,
				size_t sz, struct connchain_buffer **b)
{
  struct connchain_buffer *buf = *b;
  ssize_t i;
  int flush;

  if (buf == NULL)		/* terminated */
    return E_NOSOCKET;
  if (str == NULL)		/* termination request */
    goto finish_filter;
  if (sz == 0)			/* wrong call */
    return (0);
  if (id < 0) {			/* raw pull request */
    if (buf->saved_chain != NULL)
      _z_check_saved_buffer(id, buf);
    if (buf->in.inbuf == 0)
      return (Connchain_Get(ch, id, str, sz));
    i = (buf->in.inbuf - buf->in.bufptr);
    if (i > (ssize_t)sz)
      i = sz;
    memcpy(str, &buf->in.buf[buf->in.bufptr], i);
    if (buf->in.bufptr + i == buf->in.inbuf)
      buf->in.bufptr = buf->in.inbuf = 0;
    else
      buf->in.bufptr += i;
    return (i);
  }
  flush = Z_PARTIAL_FLUSH;
  if (buf->saved_chain == NULL) { /* read data from chain if there is a room */
    if ((*b)->error)
      i = (*b)->error;
    else if (buf->in.inbuf < sizeof(buf->in.buf)) {
      if ((i = Connchain_Get(ch, id, &buf->in.buf[buf->in.bufptr],
			     (sizeof(buf->in.buf) - buf->in.inbuf))) < 0)
	(*b)->error = i;
    } else
      i = 0;
    if (i > 0) {
      buf->in.inbuf += i;
      dprint(6, "ziplink: got compressed data from socket, size=%zd", i);
    } else if (i < 0)
      flush = Z_SYNC_FLUSH;
  } else			/* not ready yet, try to pull saved buffers */
    _z_check_saved_buffer(id, buf);
  buf->in.z.next_in = &buf->in.buf[buf->in.bufptr];
  buf->in.z.avail_in = buf->in.inbuf - buf->in.bufptr;
  buf->in.z.next_out = str;
  buf->in.z.avail_out = sz;
  i = inflate(&buf->in.z, flush); /* decompress buf->in.buf into str */
  if (i == Z_OK ||		/* some decompression was done */
      i == Z_BUF_ERROR) {	/* but might be insuffitient space to out */
    if (buf->in.z.avail_in == 0) /* all input consumed */
      buf->in.bufptr = buf->in.inbuf = 0;
    else			/* still some data left in buffer */
      buf->in.bufptr = buf->in.inbuf - buf->in.z.avail_in;
    i = (char *)buf->in.z.next_out - str;
    if (i > 0)
      dprint(6, "ziplink: decompressed data: [%-*.*s]", (int)i, (int)i, str);
    else			/* everything available decompressed */
      i = (*b)->error;		/* there might be error from connchain */
    if (i >= 0)
      return (i);
    ERROR("ziplink: got %zd from connection chain, terminating", i);
  } else
    ERROR("ziplink: Zlib returned error %zd, finishing streams.", i);
finish_filter:
  if (buf->saved_chain != NULL && Connchain_Get(&buf->saved_chain, id, NULL, 0))
    buf->saved_chain = NULL;
  flush = deflateEnd(&buf->out.z); /* Z_DATA_ERROR means data was discarded */
  if (flush != Z_OK && flush != Z_DATA_ERROR)
    ERROR("ziplink: error on Zlib output termination: %s", buf->out.z.msg);
  if (inflateEnd(&buf->in.z) != Z_OK)
    ERROR("ziplink: error on Zlib input termination: %s", buf->in.z.msg);
  i = (*b)->error;
  if (i == 0)
    i = E_NOSOCKET;
  _freezipbuff(b);
  return (i);
}

BINDING_TYPE_connchain_grow(_ccfilter_Z_init);
static int _ccfilter_Z_init (struct peer_t *peer,
	ssize_t (**recv) (struct connchain_i **, idx_t, char *, size_t, struct connchain_buffer **),
	ssize_t (**send) (struct connchain_i **, idx_t, const char *, size_t *, struct connchain_buffer **),
	struct connchain_buffer **b)
{
  char *err;
  int i;
  register struct connchain_buffer *buf;

  /* check and init the structure */
  if (b == NULL)			/* this is a test */
    return (1);
  *recv = &_ccfilter_Z_recv;		/* init the structure */
  *send = &_ccfilter_Z_send;
  *b = buf = safe_malloc (sizeof(struct connchain_buffer));
  DBG("ziplink: allocated buffer %p", buf);
  buf->in.inbuf = buf->in.bufptr = buf->out.inbuf = buf->out.bufptr = 0;
  buf->peer = peer;
  buf->next = zipbuflist;		/* add it in list */
  zipbuflist = buf;
  buf->saved_chain = peer->connchain;	/* save existing connchain */
  peer->connchain = NULL;		/* reset connchain */
  Connchain_Grow(peer, 0);		/* reinit connchain on the peer */
  buf->out.z.zalloc = &_z_alloc;
  buf->out.z.zfree = &_z_free;
  buf->out.z.opaque = NULL;
  buf->out.z.total_in = 0;
  buf->out.z.total_out = 0;
  buf->in.z.zalloc = &_z_alloc;
  buf->in.z.zfree = &_z_free;
  buf->in.z.opaque = NULL;
  buf->in.z.next_in = buf->in.buf;
  buf->in.z.avail_in = 0;
  buf->in.z.total_in = 0;
  buf->in.z.total_out = 0;
  if ((i = deflateInit(&buf->out.z, ZIPLINK_COMPRESSION_LEVEL)) == Z_OK &&
      (i = inflateInit(&buf->in.z)) != Z_OK) {
    deflateEnd(&buf->out.z);
    err = buf->in.z.msg;
  } else
    err = buf->out.z.msg;
  if (i != Z_OK) {		/* init error */
    ERROR("ziplink: Zlib initialization error: %s", err);
    _freezipbuff(b);
    return (-1);
  }
  buf->error = 0;
  /* from now on all data should be compressed */
  return (1);
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log,
 *  S_REG - report/register anything we should have in config file.
 */
static iftype_t module_signal (INTERFACE *iface, ifsig_t sig)
{
  INTERFACE *tmp;
  struct connchain_buffer *buf;
  char *termreason = "module 'ziplink' termination";

  switch (sig) {
  case S_TERMINATE:
    Delete_Binding("connchain-grow", &_ccfilter_Z_init, NULL);
    if (ShutdownR == NULL)
      ShutdownR = termreason;
    while (zipbuflist) {	/* kill every ziplink in progress */
      tmp = zipbuflist->peer->iface;
      Send_Signal(tmp->ift, tmp->name, S_TERMINATE);
      Set_Iface(tmp);		/* it may have deferred termination */
      while (Get_Request());
      Unset_Iface();
    }
    Delete_Help("ziplink");
    if (ShutdownR == termreason)
      ShutdownR = NULL;
    break;
  case S_REPORT:
    tmp = Set_Iface(iface);
    if ((buf = zipbuflist)) do {
	if (buf->peer->dname && *buf->peer->dname)
	  New_Request(tmp, F_REPORT, "Zip link: used on peer %s.",
		      buf->peer->dname);
	else
	  New_Request(tmp, F_REPORT, "Zip link: used on nonamed peer (%hd).",
		      buf->peer->socket);
	buf = buf->next;
      } while (buf);
    else
      New_Request(tmp, F_REPORT, "Module ziplink: not used.");
    Unset_Iface();
    break;
  case S_REG:
    Add_Request (I_INIT, "*", F_REPORT, "module ziplink");
    break;
  default: ;
  }
  return 0;
}

/*
 * this function called when you load a module.
 * Input: parameters string args.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
SigFunction ModuleInit (char *args)
{
  CheckVersion;
  Add_Help("ziplink");
  Add_Binding("connchain-grow", "Z", 0, 0, &_ccfilter_Z_init, NULL);
  return (&module_signal);
}
#else
SigFunction ModuleInit (char *args)
{
  ERROR ("Cannot use Zlib, recompile package to get module 'ziplink' working.");
  return (NULL);
}
#endif /* HAVE_ZLIB */
