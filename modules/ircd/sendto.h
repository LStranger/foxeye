/*
 * Copyright (C) 2010-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye IRCd module.
 */

#ifndef _IRCD_SENDTO_H
#define _IRCD_SENDTO_H

/* sends to every local user on chan; args: channel, message... */
#define ircd_sendto_chan_local(a,...) do {\
  register MEMBER *M; \
  for (M = a->users; M; M = M->prevnick) \
    if (!CLIENT_IS_ME(M->who) && CLIENT_IS_LOCAL(M->who)) \
      M->who->via->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
/* sends to other local users on chan; args: channel, client, message... */
#define ircd_sendto_chan_butone(a,b,...) do {\
  register MEMBER *M; \
  for (M = a->users; M; M = M->prevnick) \
    if (M->who != b && !CLIENT_IS_ME(M->who) && CLIENT_IS_LOCAL(M->who)) \
      M->who->via->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)

#if IRCD_MULTICONNECT
/* sends to user; args: client, message... */
#define ircd_sendto_remote(a,...) do {\
  a->cs->via->p.iface->ift |= I_PENDING; \
  if (a->cs->alt) \
    a->cs->alt->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
#define ircd_sendto_one(a,...) do {\
  if (CLIENT_IS_LOCAL(a)) \
    New_Request (a->via->p.iface, 0, __VA_ARGS__); \
  else ircd_sendto_remote (a, __VA_ARGS__); } while(0)
/* sends to remote user when using different syntax for new and old server types */
#define ircd_sendto_new(a,...) do {\
  if (a->cs->umode & A_MULTI) \
    a->cs->via->p.iface->ift |= I_PENDING; \
  if (a->cs->alt && (a->cs->alt->link->cl->umode & A_MULTI)) \
    a->cs->alt->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
#define ircd_sendto_old(a,...) do {\
  if (!(a->cs->umode & A_MULTI)) \
    a->cs->via->p.iface->ift |= I_PENDING; \
  if (a->cs->alt && !(a->cs->alt->link->cl->umode & A_MULTI)) \
    a->cs->alt->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
#else
#define ircd_sendto_one(a,...) New_Request (a->cs->via->p.iface, 0, __VA_ARGS__)
#define ircd_sendto_remote ircd_sendto_one
#define ircd_sendto_new(a,...)
#define ircd_sendto_old ircd_sendto_one
#endif

#if IRCD_MULTICONNECT /* don't send back to sender by cycle */
#define __CHECK_TRANSIT__(_a_) if (L->cl->x.token != _a_)
#else /* we never can send to sender if not back on RFC2813 server */
#define __CHECK_TRANSIT__(_a_)
#endif

/* to use those macros on messages from another server - put lines before usage:
#undef __TRANSIT__
#define __TRANSIT__ __CHECK_TRANSIT__(token)
   where token is variable containing sender's server token (binding's param)
   and those lines after usage:
#undef __TRANSIT__
#define __TRANSIT__
   */

/* sends to every server; args: ircd, from_peer, message...
   example:  ircd_sendto_servers_old (Ircd, via, ":%s QUIT :I quit", sender); */
#define ircd_sendto_servers_all(a,b,...) do {\
  register LINK *L; \
  for (L = (a)->servers; L; L = L->prev) \
    if (L->cl->via != b) \
      __TRANSIT__ L->cl->via->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
/* the same but using mask; args: ircd, from_peer, mask, message... */
#define ircd_sendto_servers_mask(a,b,c,...) do {\
  register LINK *L; \
  for (L = (a)->servers; L; L = L->prev) \
    if (simple_match (c, L->cl->lcnick) >= 0 && L->cl->via != b) \
      __TRANSIT__ L->cl->via->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
#if IRCD_MULTICONNECT
/* sends to every new type server */
#define ircd_sendto_servers_new(a,b,...) do {\
  register LINK *L; \
  for (L = (a)->servers; L; L = L->prev) \
    if ((L->cl->umode & A_MULTI) && L->cl->via != b) \
      __TRANSIT__ L->cl->via->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
/* the same but with mask */
#define ircd_sendto_servers_mask_new(a,b,c,...) do {\
  register LINK *L; \
  for (L = (a)->servers; L; L = L->prev) \
    if ((L->cl->umode & A_MULTI) && L->cl->via != b && \
	simple_match (c, L->cl->lcnick) >= 0) \
      __TRANSIT__ L->cl->via->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
/* sends to every old type server */
#define ircd_sendto_servers_old(a,b,...) do {\
  register LINK *L; \
  for (L = (a)->servers; L; L = L->prev) \
    if (!(L->cl->umode & A_MULTI) && L->cl->via != b) \
      __TRANSIT__ L->cl->via->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
/* the same but with mask */
#define ircd_sendto_servers_mask_old(a,b,c,...) do {\
  register LINK *L; \
  for (L = (a)->servers; L; L = L->prev) \
    if (!(L->cl->umode & A_MULTI) && L->cl->via != b && \
	simple_match (c, L->cl->lcnick) >= 0) \
      __TRANSIT__ L->cl->via->p.iface->ift |= I_PENDING; \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
/* sends to every new type server with ack;
   args: ircd, who, where, from_peer, message... */
#define ircd_sendto_servers_ack(i,a,b,c,...) do {\
  LINK *L; \
  for (L = (i)->servers; L; L = L->prev) \
    __TRANSIT__ if ((L->cl->umode & A_MULTI) && L->cl->via != c) { \
      L->cl->via->p.iface->ift |= I_PENDING; \
      ircd_add_ack (L->cl->via, a, b); } \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
/* the same but using mask;
   args: ircd, who, where, from_peer, mask, message... */
#define ircd_sendto_servers_mask_ack(i,a,b,c,d,...) do {\
  LINK *L; \
  for (L = (i)->servers; L; L = L->prev) \
    __TRANSIT__ if ((L->cl->umode & A_MULTI) && L->cl->via != c && \
	simple_match (d, L->cl->lcnick) >= 0) { \
      L->cl->via->p.iface->ift |= I_PENDING; \
      ircd_add_ack (L->cl->via, a, b); } \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
/* sends to every server with ack; args the same */
#define ircd_sendto_servers_all_ack(i,a,b,c,...) do {\
  LINK *L; \
  for (L = (i)->servers; L; L = L->prev) \
    __TRANSIT__ if (L->cl->via != c) { \
      L->cl->via->p.iface->ift |= I_PENDING; \
      if (L->cl->umode & A_MULTI) \
	ircd_add_ack (L->cl->via, a, b); } \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
/* the same but with mask */
#define ircd_sendto_servers_mask_all_ack(i,a,b,c,d,...) do {\
  LINK *L; \
  for (L = (i)->servers; L; L = L->prev) \
    __TRANSIT__ if (L->cl->via != c && simple_match (d, L->cl->lcnick) >= 0) { \
      L->cl->via->p.iface->ift |= I_PENDING; \
      if (L->cl->umode & A_MULTI) \
	ircd_add_ack (L->cl->via, a, b); } \
  Add_Request (I_PENDING, "*", 0, __VA_ARGS__); } while(0)
#else
#define ircd_sendto_servers_new(a,...)
#define ircd_sendto_servers_ack(a,...)
#define ircd_sendto_servers_mask_new(a,...)
#define ircd_sendto_servers_mask_ack(a,...)
#define ircd_sendto_servers_old ircd_sendto_servers_all
#define ircd_sendto_servers_mask_old ircd_sendto_servers_mask
#define ircd_sendto_servers_all_ack(i,a,b,c,...) \
  ircd_sendto_servers_all(i,c,__VA_ARGS__)
#define ircd_sendto_servers_mask_all_ack(i,a,b,c,d,...) \
  ircd_sendto_servers_mask(i,c,d,__VA_ARGS__)
#endif
#define __TRANSIT__ /* no transit by default */

//TODO: implement IWALLOPS too
/* broadcasts WALLOPS; args: ircd, text, ... */
#define ircd_sendto_wallops(i,a,...) do { \
  const char *me = ircd_mark_wallops(); \
  ircd_sendto_servers_all(i, NULL, ":%s WALLOPS :" a, me, __VA_ARGS__); } while(0)

#endif
