/*
 * Copyright (C) 2016-2017  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 *     In addition, as a special exception, the copyright holders give
 *     permission to link the code of portions of this program with the
 *     OpenSSL library under certain conditions as described in each
 *     individual source file, and distribute linked combinations
 *     including the two.
 *     You must obey the GNU General Public License in all respects
 *     for all of the code used other than OpenSSL.  If you modify
 *     file(s) with this exception, you may extend this exception to your
 *     version of the file(s), but you are not obligated to do so.  If you
 *     do not wish to do so, delete this exception statement from your
 *     version.  If you delete this exception statement from all source
 *     files in the program, then also delete it here.
 *
 * This file is a part of FoxEye 'ssl' module.
 */

#include "foxeye.h"

#ifdef USE_OPENSSL

#include "modules.h"
#include "init.h"
#include "socket.h"
#include "direct.h"
#include "sheduler.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

struct sslbuff {
  BIO *bio;
  size_t bufptr, inbuf;
  char buf[2*MB_LEN_MAX*MESSAGEMAX];
};

struct connchain_buffer {
  struct peer_t *peer;
  struct connchain_i *saved_chain;
  struct connchain_buffer *next;
  ssize_t error;
  SSL *ssl;
  struct sslbuff in, out;
  bool check_done;
};

/* global list of buffers, need it in case of module termination */
static struct connchain_buffer *sslbuflist = NULL;

static SSL_CTX *ctx = NULL;
static bool _initialized = FALSE;

static char ssl_certificate_file[PATH_MAX+1] = "";
static char ssl_key_file[PATH_MAX+1] = "";
static bool ssl_enable_bypass = FALSE;

static void _freesslbuff(struct connchain_buffer **buf)
{
  struct connchain_buffer **sb;

  for (sb = &sslbuflist; *sb; sb = &(*sb)->next)
    if (*sb == *buf)
      break;
  if (*sb != NULL)
    *sb = (*buf)->next;
  else
    ERROR("ssl: cannot find buffer %p in list to free it!", *buf);
  DBG("ssl: freeing buffer %p", *buf);
//  BIO_free((*buf)->in.bio);
//  BIO_free((*buf)->out.bio);
  SSL_free((*buf)->ssl);
  FREE(buf);
}

static void _s_check_saved_buffer(idx_t id, struct connchain_buffer *buf)
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
    dprint(6, "ssl: found stream data: size=%zd", i);
  }
  /* check if there is old data left to push from buffers into socket */
  o = 0;
  o = Connchain_Put(&buf->saved_chain, id, NULL, &o);
  /* kill chain when done */
  if (i < 0 && o < 0 && Connchain_Get(&buf->saved_chain, -1, NULL, 0))
    buf->saved_chain = NULL;
  DBG("ssl: cleared old chain");
}

/* does buffer part of _ccfilter_S_send() job */
static ssize_t _ssl_try_send_buffers(struct connchain_i **ch, idx_t id,
				     struct connchain_buffer *buf, bool check_bio)
{
  size_t so;
  ssize_t i;

  if (check_bio) {
    i = BIO_read(buf->out.bio, &buf->out.buf[buf->out.inbuf],
		 sizeof(buf->out.buf) - buf->out.inbuf);
    if (i > 0)
      buf->out.inbuf += i;
    /* else
      DBG("ssl: BIO_read error code %zd", i); */
  }
  so = buf->out.inbuf - buf->out.bufptr;
  i = Connchain_Put(ch, id, &buf->out.buf[buf->out.bufptr], &so);
  /* DBG("ssl: tried to send data, size=%zu sent=%zd", so, i); */
  if (i < 0)
    return (i);
  if (i > 0 && buf->out.inbuf > 0)
    dprint(6, "ssl: sent encrypted data, size=%zd", i);
  if (so == 0)			/* done */
    buf->out.bufptr = buf->out.inbuf = 0;
  else
    buf->out.bufptr += i;
  return i;
}

/* does chain part of _ccfilter_S_recv() job
   returns FALSE if filter should be terminated */
static bool _ssl_check_input_from_chain(struct connchain_i **ch, idx_t id,
					struct connchain_buffer **b)
{
  struct connchain_buffer *buf = *b;
  ssize_t i;

  if (buf->saved_chain == NULL) { /* read data from chain if there is a room */
    if ((*b)->error)
      i = (*b)->error;
    else if (!buf->check_done) {
      if (buf->in.inbuf < 2)
	i = Connchain_Get(ch, id, &buf->in.buf[buf->in.inbuf], 2 - buf->in.inbuf);
      else
	i = 0;
      if (i < 0)
	(*b)->error = i;
      else
	buf->in.inbuf += i;
      if (buf->in.inbuf == 2) {
	if (buf->in.buf[0] == 0x16 && buf->in.buf[1] == 3)
	  /* SSL stream version 3 */
	  buf->check_done = TRUE;
	else
	  /* it's not a SSL stream */
	  return (FALSE);
      }
      i = 0;
    } else if (buf->in.inbuf < sizeof(buf->in.buf)) {
      if ((i = Connchain_Get(ch, id, &buf->in.buf[buf->in.bufptr],
			     (sizeof(buf->in.buf) - buf->in.inbuf))) < 0)
	(*b)->error = i;
    } else
      i = 0;
    if (i > 0) {
      buf->in.inbuf += i;
      dprint(6, "ssl: got encrypted data from socket, size=%zd", i);
    }
  } else			/* not ready yet, try to pull saved buffers */
    _s_check_saved_buffer(id, buf);
  /* now process buffered data */
  i = buf->in.inbuf - buf->in.bufptr;
  if (i > 0) {
    i = BIO_write(buf->in.bio, &buf->in.buf[buf->in.bufptr], i);
    if (i <= 0) {		/* some error in BIO_write */
      DBG("ssl: BIO_write error code %zd", i);
    } else {			/* some data pushed into BIO */
      if (buf->in.inbuf == buf->in.bufptr + i) /* all input consumed */
	buf->in.bufptr = buf->in.inbuf = 0;
      else
	buf->in.bufptr += i;
    }
  }
  return (TRUE);
}

/* send into saved_chain while in early state and reject data
   kill saved chain as soon it's done */
static ssize_t _ccfilter_S_send(struct connchain_i **ch, idx_t id, const char *str,
				size_t *sz, struct connchain_buffer **b)
{
  struct connchain_buffer *buf = *b;
  size_t so;
  ssize_t i;

  if (buf == NULL)		/* terminated */
    return (E_NOSOCKET);
  if (buf->saved_chain != NULL) { /* not ready yet, try to push saved buffers */
    _s_check_saved_buffer(id, buf);
    if (buf->saved_chain != NULL)
      return (0);
  }
  if (str == NULL) {		/* asked to flush, we not call SSL here! */
    if (buf->out.inbuf)
      return (0);
    return Connchain_Put (ch, id, str, sz); /* ask next link to flush then */
  }
  i = _ssl_try_send_buffers(ch, id, buf, TRUE); /* try to push buffers now */
  if (i < 0)
    return (i);
  if (buf->out.inbuf >= (sizeof(buf->out.buf) - 16)) /* reserve 16 bytes */
    return (0);			/* not ready now */
  if (*sz == 0) {		/* a test */
    if (!SSL_is_init_finished(buf->ssl))
      return (0);
    return Connchain_Put (ch, id, str, sz); /* bounce test to next link */
  } else if (!SSL_is_init_finished(buf->ssl)) {
    SSL_do_handshake(buf->ssl);
    if (!_ssl_check_input_from_chain(ch, id, b)) /* SSL may wait for data */
      return Connchain_Put (ch, id, str, sz); /* if not SSL then bypass data */
    DBG("ssl: handshake is in progress");
    if (!SSL_is_init_finished(buf->ssl))
      return ((*b)->error);	/* there might be an error from connchain */
  }
  /* ready to process input data */
  i = SSL_write(buf->ssl, str, *sz);
  if (i > 0) {			/* some data were processed */
    *sz -= i;
    dprint(6, "ssl: pushed data: [%-*.*s]", (int)i, (int)i, str);
  } else if (i < 0) {		/* processing not available now */
    DBG("ssl: SSL_write error code %d", SSL_get_error(buf->ssl, (int)i));
    i = 0;
  }
  so = i;
  if (buf->out.inbuf != 0) {	/* trying to push buffer again */
    i = _ssl_try_send_buffers(ch, id, buf, TRUE);
    if (i < 0)
      return (i);
  }
  return (so);
}

/* termination includes saved chain if in early state */
static ssize_t _ccfilter_S_recv(struct connchain_i **ch, idx_t id, char *str,
				size_t sz, struct connchain_buffer **b)
{
  struct connchain_buffer *buf = *b;
  ssize_t i;

  if (buf == NULL)		/* terminated */
    return E_NOSOCKET;
  if (str == NULL)		/* termination request */
    goto finish_filter;
  if (sz == 0)			/* wrong call */
    return (0);
  if (id < 0) {			/* raw pull request */
    if (buf->saved_chain != NULL)
      _s_check_saved_buffer(id, buf);
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
  if (!_ssl_check_input_from_chain(ch, id, b)) { /* not a SSL data */
    i = (buf->in.inbuf - buf->in.bufptr);
    if (i > (ssize_t)sz)
      i = sz;
    memcpy(str, &buf->in.buf[buf->in.bufptr], i);
    if (buf->in.bufptr + i == buf->in.inbuf)
      Connchain_Shrink (buf->peer, *ch);
    else
      buf->in.bufptr += i;
    return (i);
  }
  if (!SSL_is_init_finished(buf->ssl)) { /* check for handshake */
    SSL_do_handshake(buf->ssl);
    i = _ssl_try_send_buffers(ch, id, buf, TRUE); /* SSL may have data to send */
    if (i < 0)
      return (i);
  }
  i = SSL_read(buf->ssl, str, sz);
  if (i <= 0) {			/* some error in SSL_read */
    /* DBG("ssl: SSL_read error code %d", SSL_get_error(buf->ssl, (int)i)); */
    i = (*b)->error;		/* there might be error from connchain */
  } else			/* got some data */
    dprint(6, "ssl: decrypted data: [%-*.*s]", (int)i, (int)i, str);
  if (i >= 0)
    return (i);
  ERROR("ssl: got %zd from connection chain, terminating", i);
finish_filter:
  if (buf->saved_chain != NULL && Connchain_Get(&buf->saved_chain, -1, NULL, 0))
    buf->saved_chain = NULL;
  i = (*b)->error;
  if (i == 0)
    i = E_NOSOCKET;
  _freesslbuff(b);
  return (i);
}

static struct connchain_buffer *_make_buffer(struct peer_t *peer,
	ssize_t (**recv) (struct connchain_i **, idx_t, char *, size_t, struct connchain_buffer **),
	ssize_t (**send) (struct connchain_i **, idx_t, const char *, size_t *, struct connchain_buffer **))
{
  struct connchain_buffer *buf;

  buf = safe_malloc (sizeof(struct connchain_buffer));
  DBG("ssl: allocated buffer %p", buf);
  *recv = &_ccfilter_S_recv;		/* init the structure */
  *send = &_ccfilter_S_send;
  buf->in.inbuf = buf->in.bufptr = buf->out.inbuf = buf->out.bufptr = 0;
  buf->peer = peer;
  buf->next = sslbuflist;		/* add it in list */
  sslbuflist = buf;
  buf->saved_chain = peer->connchain;	/* save existing connchain */
  peer->connchain = NULL;		/* reset connchain */
  Connchain_Grow(peer, 0);		/* reinit connchain on the peer */
  /* init connection and buffers */
  buf->ssl = SSL_new(ctx);
  if (buf->ssl == NULL) {
    // ... error
  }
  buf->in.bio = BIO_new(BIO_s_mem());
  if (buf->in.bio == NULL) {
    // ... error
  }
  BIO_set_mem_eof_return(buf->in.bio, -1); /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */
  buf->out.bio = BIO_new(BIO_s_mem());
  if (buf->out.bio == NULL) {
    // ... error
  }
  BIO_set_mem_eof_return(buf->out.bio, -1);
  SSL_set_bio(buf->ssl, buf->in.bio, buf->out.bio);
  buf->error = 0;
  /* from now on all data should go through SSL */
  return (buf);
}

BINDING_TYPE_connchain_grow(_ccfilter_S_init);
static int _ccfilter_S_init (struct peer_t *peer,
	ssize_t (**recv) (struct connchain_i **, idx_t, char *, size_t, struct connchain_buffer **),
	ssize_t (**send) (struct connchain_i **, idx_t, const char *, size_t *, struct connchain_buffer **),
	struct connchain_buffer **b)
{
  register struct connchain_buffer *buf;

  if (b == NULL)			/* this is a test */
    return (1);
  *b = buf = _make_buffer(peer, recv, send);
  /* start handshake as server side */
  SSL_set_accept_state(buf->ssl);
  buf->check_done = !ssl_enable_bypass;
  return (1);
}

BINDING_TYPE_connchain_grow(_ccfilter_s_init);
static int _ccfilter_s_init (struct peer_t *peer,
	ssize_t (**recv) (struct connchain_i **, idx_t, char *, size_t, struct connchain_buffer **),
	ssize_t (**send) (struct connchain_i **, idx_t, const char *, size_t *, struct connchain_buffer **),
	struct connchain_buffer **b)
{
  register struct connchain_buffer *buf;

  if (b == NULL)			/* this is a test */
    return (1);
  *b = buf = _make_buffer(peer, recv, send);
  /* start handshake as client side */
  SSL_set_connect_state(buf->ssl);
  buf->check_done = TRUE; /* no check is possible on client side */
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
  char *termreason = "module 'ssl' termination";
  const char term_signal[] = { S_TERMINATE };

  switch (sig) {
  case S_TERMINATE:
    UnregisterVariable("ssl-certificate-file");
    UnregisterVariable("ssl-key-file");
    UnregisterVariable("ssl-enable-server-bypass");
    Delete_Binding("connchain-grow", &_ccfilter_S_init, NULL);
    Delete_Binding("connchain-grow", &_ccfilter_s_init, NULL);
    if (ShutdownR == NULL)
      ShutdownR = termreason;
    while (sslbuflist) {		/* kill every SSL in progress */
      tmp = sslbuflist->peer->iface;
#if __GNUC__ >= 4
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security" /* for F_SIGNAL "string" */
#endif
      New_Request(tmp, F_SIGNAL, term_signal);
#if __GNUC__ >= 4
#pragma GCC diagnostic pop
#endif
      Set_Iface(tmp);			/* it may have deferred termination */
      while (Get_Request());
      Unset_Iface();
    }
    Delete_Help("ssl");
    if (ShutdownR == termreason)
      ShutdownR = NULL;
    /* free ctx */
    SSL_CTX_free(ctx);
    ctx = NULL;
    /* deinit library */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_remove_state(0);
#else
    FIPS_mode_set(0);
#endif
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    CRYPTO_cleanup_all_ex_data();
    break;
  case S_REPORT:
    tmp = Set_Iface(iface);
    if ((buf = sslbuflist)) do {
	if (buf->peer->dname && *buf->peer->dname)
	  New_Request(tmp, F_REPORT, _("SSL link: used on peer %s as %s."),
		      buf->peer->dname, SSL_CIPHER_get_version(SSL_get_current_cipher(buf->ssl)));
	else
	  New_Request(tmp, F_REPORT, _("SSL link: used on nonamed peer (%hd) as %s."),
		      buf->peer->socket, SSL_CIPHER_get_version(SSL_get_current_cipher(buf->ssl)));
	buf = buf->next;
      } while (buf);
    else
      New_Request(tmp, F_REPORT, _("Module ssl: not used."));
    Unset_Iface();
    break;
  case S_REG:
    Add_Request (I_INIT, "*", F_REPORT, "module ssl");
    RegisterString("ssl-certificate-file", ssl_certificate_file,
		   sizeof(ssl_certificate_file), 0);
    RegisterString("ssl-key-file", ssl_key_file, sizeof(ssl_key_file), 0);
    RegisterBoolean("ssl-enable-server-bypass", &ssl_enable_bypass);
    break;
  case S_TIMEOUT:
    /* delayed init */
    if (_initialized) {
      Add_Request (I_LOG, "*", F_WARN, "ssl: stray S_TIMEOUT signal to module!");
      break;				/* ignore it */
    }
    _initialized = TRUE;
    // SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &_no_verify);
    // SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");
    if (ssl_certificate_file[0] == '\0') {
      DBG("OpenSSL: using default certificates");
      SSL_CTX_set_default_verify_paths(ctx);
    } else if (SSL_CTX_use_certificate_file(ctx, ssl_certificate_file, SSL_FILETYPE_PEM) <= 0) {
      ERROR("OpenSSL init failed: CTX_use_certificate_file: %s",
	    ERR_error_string(ERR_get_error(), NULL));
      goto _cleanup;
    }
    if (ssl_key_file[0] == '\0') {
      WARNING("OpenSSL: no key file is set, server setup will not work");
    } else if (SSL_CTX_use_PrivateKey_file(ctx, ssl_key_file, SSL_FILETYPE_PEM) <= 0) {
      ERROR("OpenSSL init failed: CTX_use_PrivateKey_file: %s",
	    ERR_error_string(ERR_get_error(), NULL));
      goto _cleanup;
    } else if (!SSL_CTX_check_private_key(ctx)) {
      ERROR("OpenSSL init failed: CTX_check_private_key: %s",
	    ERR_error_string(ERR_get_error(), NULL));
_cleanup:
      iface->ift |= I_FINWAIT;		/* schedule suicide */
    }
    break;
  default: ;
  }
  return (0);
}

/*
 * this function called when you load a module.
 * Input: parameters string args.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
SigFunction ModuleInit (char *args)
{
  CheckVersion;
  /* lib init */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_library_init();
#else
  OPENSSL_init_ssl(0, NULL);
#endif
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  /* init ctx */
  ctx = SSL_CTX_new(SSLv23_method());
  if (!ctx) {
    ERROR("OpenSSL init failed: CTX_new: %s", ERR_error_string(ERR_get_error(), NULL));
    return (NULL);
  }
  _initialized = FALSE;
  Add_Help("ssl");
  RegisterString("ssl-certificate-file", ssl_certificate_file,
		 sizeof(ssl_certificate_file), 0);
  RegisterString("ssl-key-file", ssl_key_file, sizeof(ssl_key_file), 0);
  RegisterBoolean("ssl-enable-server-bypass", &ssl_enable_bypass);
  Add_Binding("connchain-grow", "S", 0, 0, &_ccfilter_S_init, NULL);
  Add_Binding("connchain-grow", "s", 0, 0, &_ccfilter_s_init, NULL);
  /* schedule init */
  NewTimer(I_MODULE, "ssl", S_TIMEOUT, 1, 0, 0, 0);
  return (&module_signal);
}
#else
SigFunction ModuleInit (char *args)
{
  ERROR ("Cannot use OpenSSL, recompile package to get module 'ssl' working.");
  return (NULL);
}
#endif /* USE_OPENSSL */
