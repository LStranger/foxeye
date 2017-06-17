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
  char capab[400];
} IrcdCapabServ;

static char ircd_capab_blacklist[LONG_STRING] = "";

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

/* phase 1: before PASS - send our list and receive other */
BINDING_TYPE_ircd_server_handshake(_ircd_server_handshake_capab);
static int _ircd_server_handshake_capab(INTERFACE *srv, struct peer_t *peer,
					const char *host)
{
  struct binding_t *b = NULL;
  char message[400];
  int ptr = 0;
  size_t sz;

  /* sending our CAPAB list */
  DBG("ircd-capab: advertise CAPAB to %s (%s)", peer->iface->name, host);
  strcpy(message, "CAPAB :");
  sz = strlen(message);
  while ((b = Check_Bindtable(BtIrcdCapab, NULL, U_ALL, U_ANYCH, b)))
  {
    if (sz + ptr + strlen(b->key) >= sizeof(message) - 1)
    {
      ERROR("ircd-capab: CAPAB list is too long (%d), truncating",
	    ptr + (int)strlen(b->key) + 1);
      break;
    }
    if (ptr > 0)
      message[ptr++] = ' ';
    strfcpy(&message[sz + ptr], b->key, sizeof(message) - sz - ptr);
    ptr += strlen(b->key);
  }
  sz += ptr;
  if (ptr > 0 && Peer_Put(peer, message, &sz) <= 0) /* failed! */
    return 0;
  return ptr;
}

BINDING_TYPE_ircd_register_cmd(ircd_capab);
static int ircd_capab(INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{ /* args: <list> */
  IrcdCapabServ *serv = _find_server(peer);

  if (serv != NULL || argc < 1) /* invalid server or number of arguments */
    return 0;

  serv = alloc_IrcdCapabServ();
  serv->prev = _known_servers;
  _known_servers = serv;
  serv->peer = peer;
  strfcpy(serv->capab, argv[0], sizeof(serv->capab));
  DBG("ircd-capab: got CAPAB from peer %s", peer->dname);
  return 1;
}

BINDING_TYPE_ircd_drop_unknown(_ircd_drop_unknown_capab);
static void _ircd_drop_unknown_capab(INTERFACE *srv, struct peer_t *peer,
				     const char *user, const char *host)
{
  IrcdCapabServ *serv;
  IrcdCapabServ **ptr;

  for (ptr = &_known_servers; (serv = *ptr) != NULL; ptr = &serv->prev)
    if (serv->peer == peer)
    {
      DBG("ircd-capab: dropping peer %s", peer->dname);
      *ptr = serv->prev;
      free_IrcdCapabServ(serv);
      break;
    }
}

/* phase 2 -- server registered, activate bindings */
BINDING_TYPE_ircd_got_server(_ircd_got_server_capab);
static void _ircd_got_server_capab(INTERFACE *srv, struct peer_t *peer,
				   modeflag um, unsigned short token,
				   const char *flags)
{
  IrcdCapabServ *serv = _find_server(peer);
  char *c, *next, *end;
  struct binding_t *b = NULL;

  if (serv == NULL)
  {
    DBG("ircd-capab: unknown peer %s", peer->dname);
    return;
  }
  c = serv->capab;
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
  DBG("ircd-capab: peer %s is registered", peer->dname);
}

/* phase 3 -- server disconnected, deactivate bindings */
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
      Delete_Binding("ircd-server-handshake", &_ircd_server_handshake_capab, NULL);
      Delete_Binding("ircd-drop-unknown", (Function)&_ircd_drop_unknown_capab, NULL);
      Delete_Binding("ircd-got-server", (Function)&_ircd_got_server_capab, NULL);
      Delete_Binding("ircd-lost-server", (Function)&_ircd_lost_server_capab, NULL);
      Delete_Binding("ircd-server-cmd", (Function)&ircd_capab, NULL);
      UnregisterVariable("ircd-capab-blacklist");
      Delete_Help("ircd-capab");
      _forget_(IrcdCapabServ);
      _known_servers = NULL;
      return I_DIED;
    case S_REPORT:
      // TODO......
      break;
    case S_REG:
      Add_Request(I_INIT, "*", F_REPORT, "module ircd-capab");
      RegisterString("ircd-capab-blacklist", ircd_capab_blacklist,
		     sizeof(ircd_capab_blacklist), 0);
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
  Add_Binding("ircd-server-handshake", "*", 0, 0, &_ircd_server_handshake_capab, NULL);
  Add_Binding("ircd-drop-unknown", "*", 0, 0, (Function)&_ircd_drop_unknown_capab, NULL);
  Add_Binding("ircd-got-server", "*", 0, 0, (Function)&_ircd_got_server_capab, NULL);
  Add_Binding("ircd-lost-server", "*", 0, 0, (Function)&_ircd_lost_server_capab, NULL);
  Add_Binding("ircd-register-cmd", "capab", 0, 0, (Function)&ircd_capab, NULL);
  RegisterString("ircd-capab-blacklist", ircd_capab_blacklist,
		 sizeof(ircd_capab_blacklist), 0);
  Add_Help("ircd-capab");
  return (&module_signal);
}
