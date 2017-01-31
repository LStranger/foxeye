/*
 * Copyright (C) 2017  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye project, a module 'ircd-capab'.
 */

#include <foxeye.h>
#include <modules.h>
#include <init.h>
#include <direct.h>

typedef struct IrcdCapabServ {
  struct IrcdCapabServ *prev;
  struct peer_t *peer;
} IrcdCapabServ;

ALLOCATABLE_TYPE(IrcdCapabServ, ircd_capab_serv_, prev)

static IrcdCapabServ *_known_servers = NULL;

static struct bindtable_t *BtIrcdCapab = NULL;

static inline IrcdCapabServ *_find_server(struct peer_t *peer)
{
  register IrcdCapabServ *serv;

  for (serv = _known_servers; serv; serv = serv->prev)
    if (serv->peer == peer)
      return serv;
  return NULL;
}

/* --- dummy connchain filter --- */
struct connchain_buffer { char c; };

static ssize_t _ircd_ccfilter_stub_send(struct connchain_i **c, idx_t i, const char *b,
					size_t *s, struct connchain_buffer **x)
{
  return Connchain_Put(c, i, b, s);
}

static ssize_t _ircd_ccfilter_stub_recv(struct connchain_i **c, idx_t i, char *b,
					size_t s, struct connchain_buffer **x)
{
  return Connchain_Get(c, i, b, s);
}

BINDING_TYPE_connchain_grow(_ccfilter_C_init);
static int _ccfilter_C_init(struct peer_t *peer,
			    ssize_t (**recv)(struct connchain_i **, idx_t, char *, size_t, struct connchain_buffer **),
			    ssize_t (**send)(struct connchain_i **, idx_t, const char *, size_t *, struct connchain_buffer **),
			    struct connchain_buffer **buf)
{
  if (buf == NULL)                      /* that's a check */
    return 1;
  /* do nothing, everything will be done on ircd-got-server */
  *recv = &_ircd_ccfilter_stub_recv;
  *send = &_ircd_ccfilter_stub_send;
  return 1;
}

BINDING_TYPE_ircd_got_server(_ircd_got_server_capab);
static void _ircd_got_server_capab(INTERFACE *srv, struct peer_t *peer,
				   modeflag um, unsigned short token,
				   const char *flags)
{
  IrcdCapabServ *serv;
  struct binding_t *b = NULL;
  char message[400];
  int ptr = 0;

  if (_find_server(peer))
  {
    WARNING("ircd-capab: peer %s already registered for CAPAB", peer->dname);
    return;
  }
  if (strchr(flags, 'C') == NULL) /* not our target */
    return;
  serv = alloc_IrcdCapabServ();
  serv->prev = _known_servers;
  _known_servers = serv;
  serv->peer = peer;
  DBG("ircd-capab: peer %s is registered", peer->dname);
  /* sending our CAPAB list */
  while ((b = Check_Bindtable(BtIrcdCapab, NULL, U_ALL, U_ANYCH, b)))
  {
    if (ptr + strlen(b->key) >= sizeof(message) - 1)
    {
      ERROR("ircd-capab: CAPAB list is too long (%d), truncating",
	    ptr + (int)strlen(b->key) + 1);
      break;
    }
    if (ptr > 0)
      message[ptr++] = ' ';
    strfcpy(&message[ptr], b->key, sizeof(message) - ptr);
    ptr += strlen(b->key);
  }
  if (ptr > 0)
    New_Request(peer->iface, 0, "CAPAB :%.*s", ptr, message);
}

BINDING_TYPE_ircd_lost_server(_ircd_lost_server_capab);
static void _ircd_lost_server_capab(INTERFACE *srv, struct peer_t *peer)
{
  IrcdCapabServ *serv;
  IrcdCapabServ **ptr;
  struct binding_t *b = NULL;

  for (ptr = &_known_servers; (serv = *ptr) != NULL; ptr = &serv->prev)
    if (serv->peer == peer)
    {
      DBG("ircd-capab: peer %s is unregistered", peer->dname);
      *ptr = serv->prev;
      while ((b = Check_Bindtable(BtIrcdCapab, NULL, U_ALL, U_ANYCH, b)))
	if (b->name == NULL)
	  b->func(srv, peer, NULL);
      free_IrcdCapabServ(serv);
      return;
    }
}

BINDING_TYPE_ircd_server_cmd(ircd_capab);
static int ircd_capab(INTERFACE *srv, struct peer_t *peer, unsigned short token,
		      const char *sender, const char *lcsender, int argc, const char **argv)
{ /* args: <list> */
  IrcdCapabServ *serv = _find_server(peer);
  char *c, *next, *end;
  struct binding_t *b = NULL;

  if (serv == NULL || argc < 1) /* invalid server or number of arguments */
    return 0;
  c = (char *)argv[0];
  while (*c)
  {
    next = gettoken(c, &end);
    b = Check_Bindtable(BtIrcdCapab, c, U_ALL, U_ANYCH, NULL);
    if (b && !b->name)
      b->func(srv, peer, b->key);
    c = next;
    if (*c)
      *end = ' '; /* restore the string */
  }
  return 1;
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log,
 *  S_REG - report/register anything we should have in config file.
 */
static iftype_t module_signal (INTERFACE *iface, ifsig_t sig)
{
  switch (sig)
  {
    case S_TERMINATE:
      Delete_Binding("connchain-grow", &_ccfilter_C_init, NULL);
      Delete_Binding("ircd-got-server", (Function)&_ircd_got_server_capab, NULL);
      Delete_Binding("ircd-lost-server", (Function)&_ircd_lost_server_capab, NULL);
      Delete_Binding("ircd-server-cmd", (Function)&ircd_capab, NULL);
      _forget_(IrcdCapabServ);
      _known_servers = NULL;
      return I_DIED;
    case S_REPORT:
      // TODO......
      break;
    case S_REG:
      Add_Request(I_INIT, "*", F_REPORT, "module ircd-capab");
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
  BtIrcdCapab = Add_Bindtable("ircd-capab", B_UNIQ);
  Add_Binding("connchain-grow", "C", 0, 0, &_ccfilter_C_init, NULL);
  Add_Binding("ircd-got-server", "*", 0, 0, (Function)&_ircd_got_server_capab, NULL);
  Add_Binding("ircd-lost-server", "*", 0, 0, (Function)&_ircd_lost_server_capab, NULL);
  Add_Binding("ircd-server-cmd", "capab", 0, 0, (Function)&ircd_capab, NULL);
  return (&module_signal);
}
