/*
 * Copyright (C) 2016  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye project - implementation of RusNet IRC
 * protocol extensions.
 */

#include <foxeye.h>
#include <modules.h>
#include <init.h>

#ifdef RUSNET_COMPILE

#include <direct.h>
#include <list.h>

#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include "../ircd/ircd.h"

static char _rusnet_rmotd_file[PATH_MAX+1] = "";
static long int _rusnet_eline_limit = 25;

/* This code was taken from original rusnet-ircd */
static uint32_t crc_table[256];
static bool crc_table_done = FALSE;
static char b64enc_table [64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','_','-'
	/*
	 * really there must be '+' and '/' latest two
	 * but they're inacceptable in IRC  -erra
	 */
};

static void gen_crc32table(void)	/* build the crc table */
{
  register uint32_t crc, poly;
  register int i, j;

  poly = 0xEDB88320L;
  for (i = 0; i < 256; i++)
  {
    crc = i;
    for (j = 8; j > 0; j--)
    {
      if (crc & 1)
	crc = (crc >> 1) ^ poly;
      else
	crc >>= 1;
    }
    crc_table[i] = crc;
  }
}

static uint32_t gen_crc(const char *c)	/* calculate the crc32 value */
{
  register uint32_t crc = 0xFFFFFFFF;
  const char *ch;

  if (!crc_table_done)
    gen_crc32table();

  for (ch = c; *ch; ch++)
    crc = (crc >> 8) ^ crc_table[ (crc ^ *ch) & 0xFF ];

  return (crc ^ 0xFFFFFFFF);
}

static size_t b64enc(char *str, uint32_t val, size_t bsize)
{
  register union {
    uint32_t l;
    char p[4];
  } crc;
  size_t w = 0;

  if (bsize-- <= 1)
    return 0;

  crc.l = val; //FIXME: support BE archs too

  if (w < bsize)
    str[w++] = b64enc_table[ (crc.p[0] & 0xFC) >> 2 ]; /* LSB */
  if (w < bsize)
    str[w++] = b64enc_table[ (crc.p[0] & 0x03) << 4 | (crc.p[1] & 0xF0) >> 4 ];
  if (w < bsize)
    str[w++] = b64enc_table[ (crc.p[1] & 0x0F) << 2 | (crc.p[2] & 0xC0) >> 6 ];
  if (w < bsize)
    str[w++] = b64enc_table[ crc.p[2] & 0x3F ];
  /* Cut off two bits as non-significant
  b64[4] = (crc.p[3] & 0xFC) >> 2;
  b64[5] = (crc.p[3] & 0x03) << 4;
  */
  if (w < bsize)
    str[w++] = b64enc_table[ crc.p[3] & 0x3F ]; /* MSB */

  str[w] = '\0';	/* null-terminating result string */
  return w;
}


static int _rusnet_needmoreparam(INTERFACE *srv, const char *sender, const char *cmd)
{
  New_Request(srv, 0, "461 %s %s :Not enough parameters", sender, cmd);
  return (1);
}

static inline bool _rusnet_client_is_local(INTERFACE *srv, const char *nick,
					   char *namebuf, size_t namebufsize)
{
  INTERFACE *cli;

  unistrlower(namebuf, nick, namebufsize);
  strfcat(namebuf, "@", namebufsize);
  strfcat(namebuf, srv->name, namebufsize);
  cli = Find_Iface(I_CLIENT, namebuf);
  if (!cli)
    return FALSE;
  Unset_Iface();
  return TRUE;
}

static int _rusnet_tline_bounce(INTERFACE *srv, const char *sender, const char *cmd,
				const char **argv, const char *timer, const char *reason)
{ /* args: <servermask> <nickmask> <usermask> <hostmask> */
  char target[IFNAMEMAX+1];

  /* just send to mask, ircd interface will handle it not sending back */
  if (strchr(argv[0], '.'))
    snprintf(target, sizeof(target), "%s@%s", argv[0], srv->name);
  else if (argv[0][0] == '*')
    snprintf(target, sizeof(target), "*.%s@%s", argv[0], srv->name);
  else
    snprintf(target, sizeof(target), "%s.*@%s", argv[0], srv->name);
  Add_Request(I_SERVICE, target, 0, ":%s %s %s %s %s %s %s :%s", sender, cmd,
	      argv[0], argv[1], argv[2], argv[3], timer, reason);
  Add_Request(I_LOG, srv->name, F_MODES,
	      "%s on %s!%s@%s from %s for %s hours: bounced to %s",
	      cmd, argv[1], argv[2], argv[3], sender, timer, argv[0]);
  return (1);
}

static bool _rusnet_tline(INTERFACE *srv, struct peer_t *peer, const char *mask,
			  userflag uf, const char *target, const char *timer,
			  const char *reason)
{
  char servname[NAMEMAX+1];
  char rs[280]; /* reason, max 256 bytes as in original rusnet-ircd */
  char *c;
  struct clrec_t *clr;
  long t;
  size_t ptr = 0;

  /* validate mask first */
  if (mask[0] == '*' && mask[1] == '!')
    mask += 2;
  if (mask[0] == '!')
    mask++;
  c = strchr(mask, '!');
  if (c != NULL && uf != U_DENY) /* only KLINE may have nick, see ircd module */
  {
    ERROR("ircd-rusnet: got nick mask %.*s via %s but not KLINE, ignoring it",
	  (int)(c - mask), mask, peer->dname);
    mask = c + 1;
  }
  /* prepare input */
  snprintf(servname, sizeof(servname), "@%s", srv->name);
  t = strtol(timer, NULL, 10);
  if (t <= 0)
    t = strtol(DEFAULT_TLINE_HOURS, NULL, 10);
  /* validate reason */
  if (uf & U_QUIET)
  {
    /* special support for R-line: it has to have class with limit 2 clones */
    ptr = snprintf(rs, sizeof(rs), "2 2 2 :%s", reason);
    c = strchr(rs, ':') + 1;
  }
  else if (uf & U_ACCESS)
  {
    ptr = snprintf(rs, sizeof(rs), "5 5 %ld :%s", _rusnet_eline_limit, reason);
    c = strchr(rs, ':') + 1;
  }
  else /* U_DENY */
  {
    strfcpy(rs, reason, sizeof(rs));
    c = rs;
  }
  ptr = unistrcut(c, sizeof(rs), 255);
  c[ptr] = '\0';
  for (; *c; c++)
    if (*c == ':')
      /* replace each ':' in reason with ',' to comply with rusnet-ircd */
      *((char *)c) = ',';
  /* try to add client to listfile */
  if (Add_Clientrecord(NULL, mask, 0))
  {
    ERROR("ircd-rusnet: failed to add record for %s", mask);
    return FALSE;
  }
  clr = Find_Clientrecord(mask, NULL, NULL, NULL);
  if (clr == NULL)
  {
    ERROR("ircd-rusnet: cannot find record for %s after adding it", mask);
    return FALSE;
  }
  //check if it is change or duplicate: compare target, timer, and reason
  //if duplicate then return FALSE;
  Set_Field(clr, servname, rs, Time + t * 3600);
  Set_Flags(clr, srv->name, uf);
  Set_Field(clr, "tline-target", target, 0);
  Unlock_Clientrecord(clr);
  return TRUE;
}

static bool _rusnet_untline(INTERFACE *srv, struct peer_t *peer, const char *mask,
			    userflag uf)
{
  /* find client and remove mask from it */
  const char *lname;
  userflag rf;
  struct clrec_t *clr = Find_Clientrecord(mask, &lname, &rf, srv->name);

  if (!clr || lname || (rf & uf) != uf) /* found something else */
  {
    Unlock_Clientrecord(clr);
    return FALSE;
  }
  if (Delete_Mask(clr, mask) > 0) rf = 0;
  Unlock_Clientrecord(clr);	/* record will be flushed out on next save */
  return TRUE;
}

static int _rusnet_do_rcpage(INTERFACE *srv, const char *sender,
			     const char *nick, const char *charset)
{
  char name[IFNAMEMAX+1];
  INTERFACE *cli;
  modeflag um;
  size_t ns;

  unistrlower(name, nick, sizeof(name) - 1); /* lc nick is here */
  um = Inspect_Client(srv->name, NULL, name, NULL, NULL, NULL, NULL);
  if (um & (A_SERVER | A_SERVICE))
  {
    /* invalid target */
    New_Request(srv, 0, "401 %s %s :No such nick/channel", sender, nick);
    return (1);
  }
  ns = strlen(name);
  name[ns] = '@';
  name[ns+1] = '\0';
  strfcat(name, srv->name, sizeof(name));
  cli = Find_Iface(I_CLIENT, name);
  if (cli) /* is local client */
  {
    Unset_Iface();
    /* simulate CHARSET by user */
    New_Request(srv, 0, ":%s CHARSET %s", nick, charset);
  }
  else
    /* bounce it further */
    Add_Request(I_CLIENT, name, 0, ":%s RCPAGE %s %s", sender, nick, charset);
  return (1);
}


BINDING_TYPE_ircd_server_cmd(rusnet_rmode_sb);
static int rusnet_rmode_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			   const char *sender, const char *lcsender,
			   int argc, const char **argv)
{ /* args: <nick> <modechange> */
  char name[IFNAMEMAX+1];

  if (argc < 2)
    return _rusnet_needmoreparam(srv, sender, "RMODE");
  if (_rusnet_client_is_local(srv, argv[0], name, sizeof(name)))
    /* simulate MODE by user */
    New_Request(srv, 0, ":%s MODE %s %s", argv[0], argv[0], argv[1]);
  else
    /* bounce it further */
    Add_Request(I_CLIENT, name, 0, ":%s RMODE %s %s", sender, argv[0], argv[1]);
  return (1);
}

static int _rusnet_tline_is_for_me(INTERFACE *srv, const char *servermask)
{
  const char *me;

  if (!Lname_IsOn(srv->name, NULL, NULL, &me))
  {
    ERROR("ircd-rusnet: cannot find own server name!");
    return 0;
  }
  if (simple_match(servermask, me) < 0) /* does not match */
    return 0;
  return 1;
}

static int _rusnet_tline_sb(INTERFACE *srv, struct peer_t *peer,
			    const char *sender, int argc, const char **argv,
			    const char *cmd, userflag uf, bool can_E)
{ /* args: <servermask> <nickmask> <usermask> <hostmask> [<hours>|E] [:reason] */
  char mask[HOSTMASKLEN+1];
  const char *timer;
  const char *reason;
  int is_for_me, applied;

  if (argc < 4)
    return _rusnet_needmoreparam(srv, sender, cmd);
  if (argc < 5)
    timer = DEFAULT_TLINE_HOURS;
  else
    timer = argv[4];
  if (argc < 6)
    reason = "No reason";
  else
    reason = argv[5];
  is_for_me = _rusnet_tline_is_for_me(srv, argv[0]);
  if (is_for_me)
  {
    /* make full hostmask */
    snprintf(mask, sizeof(mask), "%s!%s@%s", argv[1], argv[2], argv[3]);
    if (can_E && strcmp(timer, "E") == 0)
      applied = _rusnet_tline(srv, peer, mask, U_ACCESS, argv[0],
			      DEFAULT_TLINE_HOURS, reason);
    else
      applied = _rusnet_tline(srv, peer, mask, uf, argv[0], timer, reason);
    if (!applied)
    {
      /* there was nothing to do, skip it to avoid cycles */
      Add_Request(I_LOG, srv->name, F_MODES,
		  "%s on %s from %s for %s hours: seems already applied, dropping",
		  cmd, mask, sender, timer);
      return (1);
    }
  }
  /* if not applied yet to me then bounce it */
  return _rusnet_tline_bounce(srv, sender, cmd, argv, timer, reason);
}

BINDING_TYPE_ircd_server_cmd(rusnet_kline_sb);
static int rusnet_kline_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			   const char *sender, const char *lcsender,
			   int argc, const char **argv)
{ /* args: <servermask> <nickmask> <usermask> <hostmask> [<hours>|E] [:reason] */
  return _rusnet_tline_sb(srv, peer, sender, argc, argv, "KLINE", U_DENY, TRUE);
}

BINDING_TYPE_ircd_server_cmd(rusnet_eline_sb);
static int rusnet_eline_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			   const char *sender, const char *lcsender,
			   int argc, const char **argv)
{ /* args: <servermask> <nickmask> <usermask> <hostmask> [<hours>|E] [:reason] */
  return _rusnet_tline_sb(srv, peer, sender, argc, argv, "ELINE", U_ACCESS, FALSE);
}

BINDING_TYPE_ircd_server_cmd(rusnet_rline_sb);
static int rusnet_rline_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			   const char *sender, const char *lcsender,
			   int argc, const char **argv)
{ /* args: <servermask> <nickmask> <usermask> <hostmask> [<hours>|E] [:reason] */
  return _rusnet_tline_sb(srv, peer, sender, argc, argv, "RLINE", U_QUIET, FALSE);
}

BINDING_TYPE_ircd_server_cmd(rusnet_rcpage_sb);
static int rusnet_rcpage_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			    const char *sender, const char *lcsender,
			    int argc, const char **argv)
{ /* args: <nick> <charset> */
  if (argc < 2)
    return _rusnet_needmoreparam(srv, sender, "RCPAGE");
  return _rusnet_do_rcpage(srv, sender, argv[0], argv[1]);
}

#if OPER_TLINE
static int _rusnet_tline_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			    int argc, const char **argv, const char *cmd,
			    userflag uf)
{ /* args: <nick!user@host> <hours> [reason] */
  modeflag um = Inspect_Client(srv->name, NULL, lcnick, NULL, NULL, NULL, NULL);

  if (!(um & A_OP))
  {
#if LOCALOP_TLINE
    if (!(um & A_HALFOP))
    {
#endif
      New_Request(srv, 0, "481 %s :Permission Denied - You're not an IRC operator",
		  peer->dname); /* ERR_NOPRIVILEGES */
      return (1);
#if LOCALOP_TLINE
    }
#endif
  }
  if (argc < 2)
    return _rusnet_needmoreparam(srv, peer->dname, cmd);
  if (!_rusnet_tline(srv, peer, argv[0], uf, NULL, argv[1],
		     argc > 2 ? argv[2] : "No reason"))
  {
    //New_Request(srv, 0, "415 %s %s :Bad host mask", peer->dname, cmd);
  }
  return (1);
}

BINDING_TYPE_ircd_client_cmd(rusnet_kline_cb);
static int rusnet_kline_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			   const char *user, const char *host, const char *vhost,
			   modeflag eum, int argc, const char **argv)
{ /* args: <nick!user@host> <hours> [reason] */
  return _rusnet_tline_cb(srv, peer, lcnick, argc, argv, "KLINE", U_DENY);
}

BINDING_TYPE_ircd_client_cmd(rusnet_eline_cb);
static int rusnet_eline_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			   const char *user, const char *host, const char *vhost,
			   modeflag eum, int argc, const char **argv)
{ /* args: <nick!user@host> <hours> [reason] */
  return _rusnet_tline_cb(srv, peer, lcnick, argc, argv, "ELINE", U_ACCESS);
}

BINDING_TYPE_ircd_client_cmd(rusnet_rline_cb);
static int rusnet_rline_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			   const char *user, const char *host, const char *vhost,
			   modeflag eum, int argc, const char **argv)
{ /* args: <nick!user@host> <hours> [reason] */
  return _rusnet_tline_cb(srv, peer, lcnick, argc, argv, "RLINE", U_QUIET);
}

static int _rusnet_untline_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			      int argc, const char **argv, const char *cmd,
			      userflag uf)
{ /* args: <nick!user@host> */
  modeflag um = Inspect_Client(srv->name, NULL, lcnick, NULL, NULL, NULL, NULL);

  if (!(um & A_OP))
  {
#if LOCALOP_TLINE
    if (!(um & A_HALFOP))
    {
#endif
      New_Request(srv, 0, "481 %s :Permission Denied - You're not an IRC operator",
		  peer->dname); /* ERR_NOPRIVILEGES */
      return (1);
#if LOCALOP_TLINE
    }
#endif
  }
  if (argc < 1)
    return _rusnet_needmoreparam(srv, peer->dname, cmd);
  if (!_rusnet_untline(srv, peer, argv[0], uf))
  {
    //New_Request(srv, 0, "415 %s %s :Bad host mask", peer->dname, cmd);
  }
  return (1);
}

BINDING_TYPE_ircd_client_cmd(rusnet_unkline_cb);
static int rusnet_unkline_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			     const char *user, const char *host, const char *vhost,
			     modeflag eum, int argc, const char **argv)
{ /* args: <nick!user@host> */
  return _rusnet_untline_cb(srv, peer, lcnick, argc, argv, "UNKLINE", U_DENY);
}

BINDING_TYPE_ircd_client_cmd(rusnet_uneline_cb);
static int rusnet_uneline_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			     const char *user, const char *host, const char *vhost,
			     modeflag eum, int argc, const char **argv)
{ /* args: <nick!user@host> */
  return _rusnet_untline_cb(srv, peer, lcnick, argc, argv, "UNELINE", U_ACCESS);
}

BINDING_TYPE_ircd_client_cmd(rusnet_unrline_cb);
static int rusnet_unrline_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			     const char *user, const char *host, const char *vhost,
			     modeflag eum, int argc, const char **argv)
{ /* args: <nick!user@host> */
  return _rusnet_untline_cb(srv, peer, lcnick, argc, argv, "UNRLINE", U_QUIET);
}
#endif

#if OPER_RCPAGE
BINDING_TYPE_ircd_client_cmd(rusnet_rcpage_cb);
static int rusnet_rcpage_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			    const char *user, const char *host, const char *vhost,
			    modeflag eum, int argc, const char **argv)
{ /* args: <nick> <charset> */
  if (argc < 2)
    return _rusnet_needmoreparam(srv, peer->dname, "RCPAGE");
  return _rusnet_do_rcpage(srv, peer->dname, argv[0], argv[1]);
}
#endif

static void _rusnet_make_vhost(INTERFACE *srv, const char *rq,
			       char *vhost, const char *host, size_t vhs,
			       int add, const char *servname)
{
  strfcpy(vhost, host, vhs);
  if (add)				/* +x requested, mask host */
  {
    /* this code was taken from original rusnet-ircd source and adapted */
    if (strcmp(servname, SERVICES_SERV) != 0)
    { /*
      ** false data for usermode +x. After really long discussion
      ** it's been concluded to false last three octets of IP
      ** address and first two parts of hostname, to provide
      ** the reasonable compromise between security
      ** and channels ban lists. Host.domain.tld is mapped to
      ** crc32(host.domain.tld).crc32(domain.tld).domain.tld
      ** and domain.tld to crc32(domain.tld).crc32(tld).domain.tld
      ** respectively --erra
      **
      ** some modification there: eggdrop masking compatibility
      ** with the same hide availability
      ** Let's say crcsum() is crc32 of complete hostname. Then:
      ** a12.b34.sub.host.domain.tld -> crcsum().crc32(sub.host.domain.tld).host.domain.tld
      ** a12-b34.sub.host.domain.tld -> crcsum().crc32(sub.host.domain.tld).host.domain.tld
      ** comp.sub.host.domain.tld -> crcsum().crc32(sub.host.domain.tld).host.domain.tld
      ** a12.b34.host.domain.tld -> crcsum().crc32(b34.host.domain.tld).host.domain.tld
      ** a12-b34.host.domain.tld -> crcsum().crc32(crcsum()).host.domain.tld
      ** sub.host.domain.tld -> crcsum().crc32(crcsum()).host.domain.tld
      ** a12.b34.domain.tld -> crcsum().crc32(b34.domain.tld).domain.tld
      ** a12-b34.domain.tld -> crcsum().crc32(crcsum()).domain.tld
      ** host.domain.tld -> crcsum().crc32(crcsum()).domain.tld
      ** a12.dom2usr.tld -> crcsum().crc32(crcsum()).dom2usr.tld
      ** domain.tld -> crcsum().crc32(crcsum()).domain.tld
      ** domain. -> crcsum().crc32(domain.crcsum()).domain
      **/
      const char *s = host;
      const char *b = s + strlen(s);
      const char *c;
      int n = 0;

      for (c = s; c < b; c++)
      {
	if (*c == ':' && (++n) == 2) break;
      }

      if (c < b)		/* IPv6 address received */
      {
	int offset = strncmp(s, "2002", 4) ? c - s : c - s - 2;
	char *ptr = vhost + offset;

	*ptr++ = ':';		/* fake IPv6 separator */
	*ptr++ = '\0';		/* cut the rest of string */
	offset++;

	offset += b64enc(vhost + offset, gen_crc(ptr), vhs - offset - 1);
	vhost[offset++] = ':';
	b64enc(vhost + offset, gen_crc(host), vhs - offset);
      }
      else			/* distinguish hostname from IPv4 address */
      {
	for (c--, n = 0; c > s; c--)
	{
	  if (*c == '.' && (++n) == 3)	/* 4th dot reached */
	    break;

	  else if (*c <= '9' && *c >= '0')
	    break;
	}

	if (n)			/* hostname second level or above... duh */
	{
	  int len;

	  /* ignore digits in second-level domain part
	     when there are no minus signs  --erra */
	  if (c > s && n == 1)
	    while (c > s && *c != '.') {
	      if (*c == '-') {
		do c++;
		while (*c != '.');

		break;
	      }
	      c--;
	    }
	  else			/* *c cannot reach \0 - see above */
	    while (*c != '.')
	      c++;
	  s = c;

	  while (s > host && *(--s) != '.');

	  if (*s == '.')	/* s is part for second crc32 */
	    s++;

	  if (s == host) /* it needs crc32(crcsum()) */
	    s = vhost;

	  /* finished gathering data, let's rock */
	  len = b64enc(vhost, gen_crc(host), vhs - 1);
	  vhost[len++] = '.';
	  len += b64enc(vhost + len, gen_crc(s), vhs - len);
	  strfcpy(vhost + len, c, vhs - len);
	}
	else if (c != s) /* are there hosts w/o dots? Yes */
	{
	  /* IP address.. reverse search */
	  uint32_t crc;

	  n = 0;
	  if (!(s = strrchr(vhost, '.')))
	    goto kill_badhost;
	  *(char *)s = '\0';
	  n = s - vhost;
	  crc = gen_crc(vhost);
	  /* keep 1st octet */
	  s = strchr(vhost, '.');
	  if (!s) {
kill_badhost:
	    /* NOTE: in original rusnet-ircd the cliend was killed.
	       we cannot do it within this callback and it isn't funny after all */
	    crc = gen_crc(vhost);
	    n += b64enc(vhost + n, gen_crc(servname), vhs - n - 1);
	  }
	  else
	    n += b64enc(vhost + n, gen_crc(host), vhs - n - 1);

	  vhost[n++] = '.';
	  n += b64enc(vhost + n, crc, vhs - n);
	  strfcpy(vhost + n, ".in-addr", vhs - n);
	}
      }
    }
  }
}

BINDING_TYPE_ircd_umodechange(rusnet_umch_x);
static modeflag rusnet_umch_x(modeflag rumode, int add,
			      void (**ma)(INTERFACE *srv, const char *rq,
					  char *vhost, const char *host, size_t vhs,
					  int add, const char *servname))
{
  if (!rumode)				/* a test */
    return A_MASKED;
#if NO_DIRECT_VHOST
  if (!(rumode & A_SERVICE))
    return 0;
#endif
  if (rumode & A_QUIET)			/* +b cannot change +x */
    return 0;
  *ma = &_rusnet_make_vhost;
  return A_MASKED;
}

BINDING_TYPE_ircd_local_client(rusnet_lcl);
static void rusnet_lcl(INTERFACE *srv, struct peer_t *peer, modeflag um)
{
#ifndef NO_DEFAULT_VHOST
  if (!(um & A_QUIET))
    New_Request(srv, 0, ":%s MODE %s +x", peer->dname, peer->dname);
#endif
}

BINDING_TYPE_ircd_whois(rusnet_whois);
static void rusnet_whois(INTERFACE *srv, const char *sender, modeflag sumf,
			 const char *target, const char *thost,
			 const char *vhost, modeflag tumf)
{
  if ((tumf & A_MASKED) && (sumf & (A_OP | A_HALFOP))) /* show real host to OPERs */
  {
    New_Request(srv, 0, "327 %s %s :Real host is %s", sender, target, thost);
  }
  if (tumf & A_QUIET)			/* user is +b */
  {
    New_Request(srv, 0, "225 %s %s :is Restricted", sender, target);
  }
}

static void _rusnet_make_collided_local(char *nick, size_t ns)
{
  size_t len, i;

  len = unistrcut(nick, ns - 5, RUSNET_NICKLEN - 5); /* nickXXXXX */
  /* cut last five digits only if there are exactly five */
  for (i = 1; i <= 5 && i < len && isdigit(nick[len - i]); i++)
  if (i > 5)
    len -= 5;
  snprintf(&nick[len], ns - len, "%d",
	   10000 + (int) (60000.0 * random() / (RAND_MAX + 10000.0)));
}

static void _rusnet_make_collided(char *newnick, const char *nick, size_t ns,
				  const char *serv)
{
  size_t len;

  *newnick = '1';
  len = unistrcut(nick, ns - 6, RUSNET_NICKLEN - 6); /* 1nickXXXXX */
  strfcpy(newnick + 1, nick, len + 1);
  b64enc(newnick + len + 1, gen_crc(serv), ns - len - 1);
}

BINDING_TYPE_ircd_collision(rusnet_coll);
static int rusnet_coll(INTERFACE *srv, char *new, size_t nsize,
		       const char *cserv, const char *nserv)
{
  if (cserv == NULL)
  {
    /* rename local user */
    _rusnet_make_collided_local(new, nsize);
  }
  else
  {
    char collided[MB_LEN_MAX*NICKLEN+1];
    /* rename old nick */
    strfcpy(collided, new, sizeof(collided));
    _rusnet_make_collided(new, collided, nsize, cserv);
  }
  /* ask to do rename */
  return 2;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_z);
static modeflag rusnet_mch_z(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && ((rchmode & (A_OP | A_HALFOP | A_ADMIN)) || !rchmode))
    return A_ASCIINICK;
  return 0;
}

BINDING_TYPE_ircd_check_modechange(rusnet_cmch);
static int rusnet_cmch(INTERFACE *u, modeflag umode, const char *chname,
		       modeflag cmode, int add, modeflag chg, const char *tgt,
		       modeflag tumode, modeflag tcmode)
{
  /* check for non-ascii nick for ascii-only channel */
  if (add && chg == 0 && (cmode & A_ASCIINICK))
    for (; *tgt; tgt++)
      if (*((uint8_t *)tgt) <= 0x20 || *((uint8_t *)tgt) > 0x7f)
      {
	if (u != NULL)
	{
	  tgt = strchr(u->name, '@'); /* split off network name */
	  add = (++tgt) - (const char *)u->name; /* reuse int */
	  if (!Lname_IsOn(tgt, NULL, NULL, &tgt))
	    tgt = "server"; /* is this ever possible? */
	  New_Request(u, 0, ":%s 470 %.*s %s :Only latin-coded nicknames allowed (+z)",
		      tgt, add, u->name, chname);
	}
	return 0;
      }
  /* limitations for R-Mode */
  if (umode & A_QUIET)
    return 0;
  if (add && (chg & (A_OP | A_HALFOP | A_VOICE)) && (tumode & A_QUIET))
    return 0;
  return 1;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_c);
static modeflag rusnet_mch_c(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && ((rchmode & (A_OP | A_HALFOP | A_ADMIN)) || !rchmode))
    return A_NOCOLOR;
  return 0;
}

BINDING_TYPE_ircd_check_message(rusnet_check_message);
static int rusnet_check_message(modeflag umode, modeflag mmode, char *msg)
{
  /* check for color in msg for colorless channel */
  if (mmode & A_NOCOLOR)
  {
    if (strchr(msg, 0x3))		/* mIRC color code */
      return 0;
  }
  /* pass to next filter */
  return -1;
}

BINDING_TYPE_ircd_umodechange(rusnet_umch_b);
static modeflag rusnet_umch_b(modeflag rumode, int add,
			      void (**ma)(INTERFACE *srv, const char *rq,
					  char *vhost, const char *host, size_t vhs,
					  int add, const char *servname))
{
  if (rumode && !add)			/* cannot do -b */
    return 0;
  //FIXME: set ma for numeric
  return A_QUIET;
}

BINDING_TYPE_ircd_auth(rusnet_auth);
static int rusnet_auth(struct peer_t *peer, char *user, char *host, const char **msg,
		       modeflag *umode)
{
  Unset_Iface(); /* mandatory call! */
  /* it's called after ircd's binding so class and umode already set */
  if (*umode & A_QUIET)
  {
    /* right, rewrite ident */
    if (user[0] != '~' && user[0] != '^')
    {
      memmove(&user[1], user, IDENTLEN - 1);
      user[IDENTLEN] = '\0';
    }
    user[0] = '%';
  }
  return 1;
}

BINDING_TYPE_ircd_client_filter(rusnet_check_join);
static int rusnet_check_join(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			     int argc, const char **argv)
{ /* args: <channel> [,<channel> ...] [<key> [,<key> ... ]] | 0 */
  if (argc < 1 || strcmp(argv[0], "0") == 0)
    return 1; /* handled by ircd */
  if (umode & A_QUIET)
  {
    char *c;

    /* allowed to join to # channels only */
    if (argv[0][0] != '#')
    {
      New_Request(srv, 0, "484 %s :Your connection is restricted!", peer->dname);
      return 0;
    }
    c = strchr(argv[0], ',');
    /* if comma encountered while user is Rlined, erase rest of list */
    if (c)
      *c = '\0';
    return 5; /* increased penalty */
  }
  return 1;
}

BINDING_TYPE_ircd_client_filter(rusnet_check_penalty);
static int rusnet_check_penalty(INTERFACE *srv, struct peer_t *peer, modeflag umode,
				int argc, const char **argv)
{
  if (umode & A_QUIET)
    return 5; /* increased penalty */
  return 1;
}

BINDING_TYPE_ircd_client_filter(rusnet_check_part);
static int rusnet_check_part(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			     int argc, const char **argv)
{ /* args: <channel>[,<channel> ...] [<Part Message>] */
  if ((umode & A_QUIET) && argc > 1)
    *((char *)argv[1]) = '\0'; /* no custom PART message */
  return 1;
}

BINDING_TYPE_ircd_client_filter(rusnet_check_quit);
static int rusnet_check_quit(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			     int argc, const char **argv)
{ /* args: [<Quit Message>] */
  if ((umode & A_QUIET) && argc > 0)
    *((char *)argv[0]) = '\0'; /* no custom QUIT message */
  return 1;
}

BINDING_TYPE_ircd_client_filter(rusnet_check_topic);
static int rusnet_check_topic(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			      int argc, const char **argv)
{ /* args: <channel> <topic> */
  char lcname[MB_LEN_MAX*CHANNAMELEN+1];
  modeflag cf;

  if (argc != 2)
    return 1;
  unistrlower(lcname, peer->dname, sizeof(lcname));
  cf = Inspect_Client(srv->name, argv[0], lcname, NULL, NULL, NULL, NULL);
  DBG("ircd-rusnet: TOPIC by %s on %s: flags are %#x", peer->dname, argv[0], cf);
  if ((cf & (A_OP | A_HALFOP)) != A_HALFOP)
    /* handled by ircd */
    return 1;
  /* send to ircd to process anyway */
  New_Request(srv, 0, ":%s TOPIC %s :%s", peer->dname, argv[0], argv[1]);
  /* it's done, do not process further */
  return 0;
}

BINDING_TYPE_ircd_client_filter(rusnet_check_kick);
static int rusnet_check_kick(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			     int argc, const char **argv)
{ /* args: <channel> <user> [<comment>] */
  char lcname[MB_LEN_MAX*CHANNAMELEN+1];
  modeflag cf;

  /* FIXME: only supported form is a single user and a single channel */
  if (argc < 2)
    return 1;
  unistrlower(lcname, peer->dname, sizeof(lcname));
  cf = Inspect_Client(srv->name, argv[0], lcname, NULL, NULL, NULL, NULL);
  DBG("ircd-rusnet: KICK by %s on %s: flags are %#x", peer->dname, argv[0], cf);
  if ((cf & (A_OP | A_HALFOP)) != A_HALFOP)
    /* handled by ircd */
    return 1;
  unistrlower(lcname, argv[1], sizeof(lcname));
  cf = Inspect_Client(srv->name, argv[0], lcname, NULL, NULL, NULL, NULL);
  if (cf == 0)
    /* no such user in the channel: let ircd send diagnostics */
    return 1;
  if (cf & (A_OP | A_HALFOP))
    /* seniority: don't kick other operators */
    return 1;
  /* send to ircd to process anyway */
  if (argc == 2)
    New_Request(srv, 0, ":%s KICK %s %s", peer->dname, argv[0], argv[1]);
  else
    New_Request(srv, 0, ":%s KICK %s %s :%s", peer->dname, argv[0], argv[1], argv[2]);
  /* it's done, do not process further */
  return 0;
}

static int _rusnet_check_msg(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			     bool notice, int argc, const char **argv)
{
  if (argc < 1)
    return 1; /* ircd will handle that */
  if (umode & A_QUIET)
  {
    if (strchr(argv[0], ','))
    {
      if (!notice) /* ERR_TOOMANYTARGETS */
	New_Request(srv, 0, "407 %s %s :Too many recipients. No Message Delivered.",
		    peer->dname, peer->dname);
      return 0;
    }
    if (argv[0][0] != '#')
    {
      char name[MB_LEN_MAX*NICKLEN+1];
      unistrlower(name, argv[0], sizeof(name));
      modeflag tm = Inspect_Client(srv->name, NULL, name, NULL, NULL, NULL, NULL);
      if (!(tm & (A_OP | A_SERVICE)))
      {
	if (!notice) /* ERR_RESTRICTED */
	  New_Request(srv, 0, "484 %s :Your connection is restricted!", peer->dname);
	return 0;
      }
    }
    return 5; /* increased penalty */
  }
  return 1;
}

BINDING_TYPE_ircd_client_filter(rusnet_check_msg);
static int rusnet_check_msg(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			    int argc, const char **argv)
{
  return _rusnet_check_msg(srv, peer, umode, FALSE, argc, argv);
}

BINDING_TYPE_ircd_client_filter(rusnet_check_ntc);
static int rusnet_check_ntc(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			    int argc, const char **argv)
{
  return _rusnet_check_msg(srv, peer, umode, TRUE, argc, argv);
}

BINDING_TYPE_ircd_client_filter(rusnet_check_nick);
static int rusnet_check_nick(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			     int argc, const char **argv)
{
  if ((umode & A_QUIET) && peer->dname[0]) /* allow registering but not change */
  {
    /* ERR_RESTRICTED */
    New_Request(srv, 0, "484 %s :Your connection is restricted!", peer->dname);
    return 0;
  }
  return 1;
}

BINDING_TYPE_ircd_client_filter(rusnet_check_no_b);
static int rusnet_check_no_b(INTERFACE *srv, struct peer_t *peer, modeflag umode,
			     int argc, const char **argv)
{
  if (umode & A_QUIET)
  {
    /* ERR_RESTRICTED */
    New_Request(srv, 0, "484 %s :Your connection is restricted!", peer->dname);
    return 0;
  }
  return 1;
}

BINDING_TYPE_ircd_check_send(rusnet_ics_no_b);
static int rusnet_ics_no_b(INTERFACE *srv, struct peer_t *tgt, modeflag tum, char *msg,
			   size_t ms)
{
  if (tum & A_QUIET)
    return 0;
  return 1;
}

static char *IrcdRMotd = NULL;
static size_t IrcdRMotdSize = 0;
static time_t IrcdRMotdTime = 0;
static char IrcdRMotdTimeStr[64];

/* it's _ircd_check_motd() from ircd module but for RMotd instead */
static size_t _rusnet_check_rmotd(void)
{
  int fd;
  size_t i;
  struct stat st;
  struct tm tm;

  if (stat(_rusnet_rmotd_file, &st) < 0) {
    /* we are in main chain now so strerror() should be safe */
    dprint(3, "ircd-rusnet: cannot stat RMOTD file: %s", strerror(errno));
    return 0;
  }
  if (IrcdRMotdTime == st.st_mtime)
    return IrcdRMotdSize;
  IrcdRMotdTime = st.st_mtime;
  if (st.st_size > MOTDMAXSIZE)		/* it should be reasonable */
  {
    FREE (&IrcdRMotd);
    IrcdRMotdSize = 0;
    return 0;
  }
  fd = open (_rusnet_rmotd_file, O_RDONLY);
  if (fd < 0)				/* no access, keep old */
    return IrcdRMotdSize;
  safe_realloc ((void **)&IrcdRMotd, st.st_size + 1);
  IrcdRMotdSize = read (fd, IrcdRMotd, st.st_size);
  close (fd);
  localtime_r (&IrcdRMotdTime, &tm);
  strftime (IrcdRMotdTimeStr, sizeof(IrcdRMotdTimeStr), "%c", &tm);
  /* TODO: support charset definition as ##$charset <name> in first line ? */
  for (i = 0; i < IrcdRMotdSize; i++)
  {
    if (IrcdRMotd[i] == '\r')
    {
      if (i < IrcdRMotdSize - 1 && IrcdRMotd[i+1] == '\n')
        IrcdRMotd[i] = ' ';
      else
        IrcdRMotd[i] = '\0';
    }
    else if (IrcdRMotd[i] == '\n')
      IrcdRMotd[i] = '\0';
  }
  IrcdRMotd[IrcdRMotdSize] = '\0';
  return IrcdRMotdSize;
}

BINDING_TYPE_ircd_check_send(rusnet_ics_motdend);
static int rusnet_ics_motdend(INTERFACE *srv, struct peer_t *tgt, modeflag tum, char *msg,
			      size_t ms)
{
  if (tum & A_QUIET)
  {
    size_t got, ptr;

    /* motd was discarded, send our now */
    got = _rusnet_check_rmotd();
    if (got == 0)
    {
      New_Request(srv, 0, "422 %s :MOTD File is missing", tgt->dname); /* ERR_NOMOTD */
      return 0;
    }
    ptr = 0;
    New_Request(srv, 0, "375 %s :- %s Message of the day - ", tgt->dname,
		srv->name); /* RPL_MOTDSTART */
    while (ptr < got)
    {
      New_Request(srv, 0, "372 %s :- %s", tgt->dname, &IrcdRMotd[ptr]); /* RPL_MOTD */
      ptr += (strlen (&IrcdRMotd[ptr]) + 1);
    }
    New_Request(srv, 0, "376 %s :End of MOTD command", tgt->dname); /* RPL_ENDOFMOTD */
    return 0;
  }
  return 1;
}

BINDING_TYPE_ircd_whochar(iwc_rusnet);
static char iwc_rusnet(char tc)
{
  if (tc == 'h') /* halfop */
    return '%';
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_h);
static modeflag rusnet_mch_h(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (target && (!rchmode || rchmode & (A_OP | A_ADMIN)))
    return A_HALFOP;
  return 0;
}

/* halfops can change +l +v +b +e +I +m +n +t +k +i */
BINDING_TYPE_ircd_modechange(rusnet_mch_l);
static modeflag rusnet_mch_l(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && (rchmode & A_HALFOP))
    return A_LIMIT; /* everything else is done by ircd */
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_v);
static modeflag rusnet_mch_v(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (target && (rchmode & A_HALFOP))
    return A_VOICE;
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_b);
static modeflag rusnet_mch_b(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && (rchmode & A_HALFOP))
    return A_DENIED;
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_e);
static modeflag rusnet_mch_e(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && (rchmode & A_HALFOP))
    return A_EXEMPT;
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_I);
static modeflag rusnet_mch_I(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && (rchmode & A_HALFOP) && (tmode & A_INVITEONLY))
    return A_INVITED;
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_m);
static modeflag rusnet_mch_m(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && (rchmode & A_HALFOP))
    return A_MODERATED;
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_n);
static modeflag rusnet_mch_n(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && (rchmode & A_HALFOP))
    return A_NOOUTSIDE;
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_t);
static modeflag rusnet_mch_t(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && (rchmode & A_HALFOP))
    return A_TOPICLOCK;
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_k);
static modeflag rusnet_mch_k(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && (rchmode & A_HALFOP))
    return A_KEYSET;
  return 0;
}

BINDING_TYPE_ircd_modechange(rusnet_mch_i);
static modeflag rusnet_mch_i(modeflag rchmode, modeflag rmode, const char *target,
			     modeflag tmode, modeflag tumode, int add, char chtype,
			     int (**ma)(INTERFACE *srv, const char *rq,
					const char *ch, int add, const char **param))
{
  if (!target && (rchmode & A_HALFOP))
    return A_INVITEONLY;
  return 0;
}

typedef struct {
  INTERFACE *srv;
  const char *rq;
  const char *net;
  const char *msg;
  time_t exp;
  int numeric;
  int host;
  char letter;
} RusnetStatsRcvr;

static int _rusnet_qlist_r(INTERFACE *tmp, REQUEST *r)
{
  if (r)
  {
    char *c = r->string;
    RusnetStatsRcvr *rcvr = tmp->data;
    struct clrec_t *clr;

    if (tmp->qsize)                     /* do recursion to consume queue */
      Get_Request();
    while (*c)
    {
      char *cnext = gettoken(c, NULL);
      if (!rcvr->host && strchr(c, '@') == NULL)
      {
	/* Lname found instead */
	lid_t lid = FindLID(c);
	userflag uf = 0;

	rcvr->host = 1;
	clr = Lock_byLID(lid);
	if (clr)
	{
	  rcvr->msg = safe_strdup(Get_Field(clr, rcvr->net, &rcvr->exp));
	  uf = Get_Flags(clr, rcvr->net);
	  Unlock_Clientrecord(clr);
	}
	/* get all hosts for Lname but if it's not a server */
	if (!(uf & U_UNSHARED) && Get_Hostlist(tmp, lid))
	  Get_Request();
	rcvr->host = 0;
	FREE(&rcvr->msg);
	rcvr->exp = 0;
      }
      else
      {
	const char *msg = NULL, *m, *r;
	time_t in;

	if (!rcvr->host) {
	  clr = Find_Clientrecord(c, NULL, NULL, NULL);
	  if (clr)
	  {
	    msg = safe_strdup(Get_Field(clr, rcvr->net, &in));
	    Unlock_Clientrecord(clr);
	  }
	} else
	  in = rcvr->exp;
	if (msg)
	  m = msg;
	else if (rcvr->msg)
	  m = rcvr->msg;
	else
	  m = "";
	r = strchr(m, ':');
	if (r)
	  m = r+1;
	if (in == 0) /* permament */
	  New_Request(rcvr->srv, 0, "%03d %s %c %s * * 0 :%s", rcvr->numeric,
		      rcvr->rq, rcvr->letter, c, m);
	else if (in > Time)
	{
	  time_t times;
	  char tch = 's';

	  times = in - Time;
	  if (times > 59)
	  {
	    times /= 60;
	    tch = 'm';
	    if (times > 59)
	    {
	      times /= 60;
	      tch = 'h';
	      if (times > 23)
	      {
		times /= 24;
		tch = 'd';
	      }
	    }
	  }
	  New_Request(rcvr->srv, 0, "%03d %s %c %s * %+d%c 0 :%s", rcvr->numeric,
		      rcvr->rq, rcvr->letter, c, (int)times, tch, m);
	}
	FREE(&msg);
      }
      c = cnext;
    }
  }
  return REQ_OK;
}

static void _rusnet_stats(INTERFACE *srv, const char *rq, userflag uf,
			  int numeric, char letter)
{
  RusnetStatsRcvr rcvr;
  char n[NAMEMAX+2];
  INTERFACE *tmp;

  rcvr.srv = srv;
  rcvr.rq = rq;
  rcvr.net = n;
  rcvr.msg = NULL;
  rcvr.numeric = numeric;
  rcvr.host = 0;
  rcvr.letter = letter;
  n[0] = '@';
  strfcpy (&n[1], srv->name, sizeof(n)-1);
  tmp = Add_Iface(I_TEMP, NULL, NULL, &_rusnet_qlist_r, &rcvr);
  Set_Iface(tmp);
  if (Get_Clientlist(tmp, uf, n, "*"))
    Get_Request(); /* it will do recurse itself */
  Unset_Iface();
  tmp->data = NULL;
  tmp->ift = I_DIED;
}

BINDING_TYPE_ircd_stats_reply(rusnet_stats_k);
static void rusnet_stats_k(INTERFACE *srv, const char *rq, modeflag umode)
{
  if (umode & (A_OP | A_HALFOP))
    _rusnet_stats(srv, rq, U_DENY, 216, 'K');
  else
    New_Request(srv, 0, "481 %s :Permission Denied - You're not an IRC operator", rq);
}

BINDING_TYPE_ircd_stats_reply(rusnet_stats_e);
static void rusnet_stats_e(INTERFACE *srv, const char *rq, modeflag umode)
{
  if (umode & (A_OP | A_HALFOP))
    _rusnet_stats(srv, rq, U_ACCESS, 216, 'E');
  else
    New_Request(srv, 0, "481 %s :Permission Denied - You're not an IRC operator", rq);
}

BINDING_TYPE_ircd_stats_reply(rusnet_stats_r);
static void rusnet_stats_r(INTERFACE *srv, const char *rq, modeflag umode)
{
  if (umode & (A_OP | A_HALFOP))
    _rusnet_stats(srv, rq, U_QUIET, 226, 'R');
  else
    New_Request(srv, 0, "481 %s :Permission Denied - You're not an IRC operator", rq);
}

static int _rusnet_call_services(INTERFACE *srv, struct peer_t *peer,
				 const char *lcnick, modeflag mf,
				 const char *serv, modeflag um, int argc,
				 const char **argv)
{
  const char *host = NULL, *ident = NULL;
  char buf[MESSAGEMAX];
  size_t ptr;

  if (argc < 1 || argv[0][0] == 0)
  {
    New_Request(srv, 0, "412 %s :No text to send", peer->dname); /* ERR_NOTEXTTOSEND */
    return (1);
  }
  /* verify if client has required usermode */
  if ((um & mf) != mf)
  {
    New_Request(srv, 0, "481 %s :Permission Denied - You're not an IRC operator",
		peer->dname); /* ERR_NOPRIVILEGES */
    return (1);
  }
  /* verify if we have the service online and not a fake one */
  um = Inspect_Client(srv->name, NULL, serv, &ident, &host, NULL, NULL);
  if (um == 0 || safe_strcmp(ident, SERVICES_IDENT) != 0 ||
      safe_strcmp(host, SERVICES_HOST) != 0)
  {
    New_Request(srv, 0, "408 %s %s :No such service", peer->dname, serv);
    return (1);
  }
  /* compose all args into a single message */
  while (argc > 0)
  {
    if (ptr > 0 && ptr < MESSAGEMAX - 2)
      buf[ptr++] = ' ';
    strfcpy(&buf[ptr], argv[0], MESSAGEMAX - ptr);
    ptr = strlen(buf);
    argv++;
    argc--;
  }
  New_Request(srv, 0, ":%s PRIVMSG %s@" SERVICES_SERV " :%s", peer->dname, serv,
	      buf);
  //FIXME: that was ugly hack, need to send SQUERY instead!
  return (1);
}

BINDING_TYPE_ircd_client_cmd(rusnet_nickserv_cb);
static int rusnet_nickserv_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			      const char *user, const char *host, const char *vhost,
			      modeflag eum, int argc, const char **argv)
{ /* args: <command ...> */
  return _rusnet_call_services(srv, peer, lcnick, 0, "NickServ", eum, argc, argv);
}

BINDING_TYPE_ircd_client_cmd(rusnet_chanserv_cb);
static int rusnet_chanserv_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			      const char *user, const char *host, const char *vhost,
			      modeflag eum, int argc, const char **argv)
{ /* args: <command ...> */
  return _rusnet_call_services(srv, peer, lcnick, 0, "ChanServ", eum, argc, argv);
}

BINDING_TYPE_ircd_client_cmd(rusnet_memoserv_cb);
static int rusnet_memoserv_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			      const char *user, const char *host, const char *vhost,
			      modeflag eum, int argc, const char **argv)
{ /* args: <command ...> */
  return _rusnet_call_services(srv, peer, lcnick, 0, "MemoServ", eum, argc, argv);
}

BINDING_TYPE_ircd_client_cmd(rusnet_operserv_cb);
static int rusnet_operserv_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			      const char *user, const char *host, const char *vhost,
			      modeflag eum, int argc, const char **argv)
{ /* args: <command ...> */
  return _rusnet_call_services(srv, peer, lcnick, A_OP, "OperServ", eum, argc, argv);
}

BINDING_TYPE_ircd_isupport(rusnet_isupport);
static void rusnet_isupport(char *buff, size_t bufsize)
{
  strfcpy(buff, "PENALTY FNC", bufsize);
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
      UnregisterVariable("rusnet-rmotd-file");
      UnregisterVariable("rusnet-eline-limit");
      Delete_Binding("ircd-server-cmd", (Function)&rusnet_rmode_sb, NULL);
      Delete_Binding("ircd-server-cmd", (Function)&rusnet_kline_sb, NULL);
      Delete_Binding("ircd-server-cmd", (Function)&rusnet_eline_sb, NULL);
      Delete_Binding("ircd-server-cmd", (Function)&rusnet_rline_sb, NULL);
      Delete_Binding("ircd-server-cmd", (Function)&rusnet_rcpage_sb, NULL);
#if OPER_TLINE
      Delete_Binding("ircd-client-cmd", &rusnet_kline_cb, NULL);
      Delete_Binding("ircd-client-cmd", &rusnet_eline_cb, NULL);
      Delete_Binding("ircd-client-cmd", &rusnet_rline_cb, NULL);
      Delete_Binding("ircd-client-cmd", &rusnet_unkline_cb, NULL);
      Delete_Binding("ircd-client-cmd", &rusnet_uneline_cb, NULL);
      Delete_Binding("ircd-client-cmd", &rusnet_unrline_cb, NULL);
#endif
#if OPER_RCPAGE
      Delete_Binding("ircd-client-cmd", &rusnet_rcpage_cb, NULL);
#endif
      Delete_Binding("ircd-umodechange", (Function)&rusnet_umch_x, NULL);
      Delete_Binding("ircd-local-client", (Function)&rusnet_lcl, NULL);
      Delete_Binding("ircd-whois", (Function)&rusnet_whois, NULL);
      Delete_Binding("ircd-collision", (Function)&rusnet_coll, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_z, NULL);
      Delete_Binding("ircd-check-modechange", &rusnet_cmch, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_c, NULL);
      Delete_Binding("ircd-check-message", &rusnet_check_message, NULL);
      Delete_Binding("ircd-umodechange", (Function)&rusnet_umch_b, NULL);
      Delete_Binding("ircd-auth", &rusnet_auth, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_msg, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_ntc, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_nick, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_no_b, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_join, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_penalty, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_part, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_quit, NULL);
      Delete_Binding("ircd-check-send", &rusnet_ics_no_b, NULL); //RPL_YOURHOST
      Delete_Binding("ircd-check-send", &rusnet_ics_motdend, NULL); //ERR_NOMOTD
      /* support channel halfops (+h) */
      Delete_Binding("ircd-whochar", (Function)&iwc_rusnet, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_h, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_l, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_v, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_b, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_e, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_I, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_m, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_n, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_t, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_k, NULL);
      Delete_Binding("ircd-modechange", (Function)&rusnet_mch_i, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_topic, NULL);
      Delete_Binding("ircd-client-filter", &rusnet_check_kick, NULL);
      Delete_Binding ("ircd-stats-reply", (Function)&rusnet_stats_k, NULL);
      Delete_Binding ("ircd-stats-reply", (Function)&rusnet_stats_e, NULL);
      Delete_Binding ("ircd-stats-reply", (Function)&rusnet_stats_r, NULL);
      Delete_Binding("ircd-isupport", (Function)&rusnet_isupport, NULL);
      Delete_Binding("ircd-client-cmd", &rusnet_nickserv_cb, NULL);
      Delete_Binding("ircd-client-cmd", &rusnet_chanserv_cb, NULL);
      Delete_Binding("ircd-client-cmd", &rusnet_memoserv_cb, NULL);
      Delete_Binding("ircd-client-cmd", &rusnet_operserv_cb, NULL);
      Send_Signal(I_MODULE, "ircd*", S_FLUSH); /* inform modules about changes */
      FREE(&IrcdRMotd);
      IrcdRMotdSize = 0;
      return I_DIED;
    case S_REPORT:
      // TODO......
      break;
    case S_REG:
      Add_Request(I_INIT, "*", F_REPORT, "module ircd-rusnet");
      RegisterString("rusnet-rmotd-file", _rusnet_rmotd_file,
		     sizeof(_rusnet_rmotd_file), 0);
      RegisterInteger("rusnet-eline-limit", &_rusnet_eline_limit);
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
  void *ptr;

  CheckVersion;
  /* if we cannot override NICKLEN then fail */
  if (!GetVariable("ircd-nicklen", VARIABLE_CONSTANT, &ptr))
    return NULL;
  snprintf((char *)ptr, 3, "%u", RUSNET_NICKLEN); /* get it tweaked on S_FLUSH */
  /* register variables */
  RegisterString("rusnet-rmotd-file", _rusnet_rmotd_file,
		 sizeof(_rusnet_rmotd_file), 0);
  RegisterInteger("rusnet-eline-limit", &_rusnet_eline_limit);
  /* support rusnet-specific commands: KLINE RMODE RLINE RCPAGE */
  Add_Binding("ircd-server-cmd", "rmode", 0, 0, (Function)&rusnet_rmode_sb, NULL);
  Add_Binding("ircd-server-cmd", "kline", 0, 0, (Function)&rusnet_kline_sb, NULL);
  Add_Binding("ircd-server-cmd", "eline", 0, 0, (Function)&rusnet_eline_sb, NULL);
  Add_Binding("ircd-server-cmd", "rline", 0, 0, (Function)&rusnet_rline_sb, NULL);
  Add_Binding("ircd-server-cmd", "rcpage", 0, 0, (Function)&rusnet_rcpage_sb, NULL);
#if OPER_TLINE
  Add_Binding("ircd-client-cmd", "kline", 0, 0, &rusnet_kline_cb, NULL);
  Add_Binding("ircd-client-cmd", "eline", 0, 0, &rusnet_eline_cb, NULL);
  Add_Binding("ircd-client-cmd", "rline", 0, 0, &rusnet_rline_cb, NULL);
  Add_Binding("ircd-client-cmd", "unkline", 0, 0, &rusnet_unkline_cb, NULL);
  Add_Binding("ircd-client-cmd", "uneline", 0, 0, &rusnet_uneline_cb, NULL);
  Add_Binding("ircd-client-cmd", "unrline", 0, 0, &rusnet_unrline_cb, NULL);
#endif
#if OPER_RCPAGE
  Add_Binding("ircd-client-cmd", "rcpage", 0, 0, &rusnet_rcpage_cb, NULL);
#endif
  /* support VHOST feature (+x usermode) */
  Add_Binding("ircd-umodechange", "x", 0, 0, (Function)&rusnet_umch_x, NULL);
  Add_Binding("ircd-local-client", "*", 0, 0, (Function)&rusnet_lcl, NULL);
  Add_Binding("ircd-whois", "*", 0, 0, (Function)&rusnet_whois, NULL);
  /* rusnet-type collision resolving */
  Add_Binding("ircd-collision", "rusnet", 0, 0, &rusnet_coll, NULL);
  /* support latin-only channels (+z channelmode) */
  Add_Binding("ircd-modechange", "z", 0, 0, (Function)&rusnet_mch_z, NULL);
  Add_Binding("ircd-check-modechange", "*", 0, 0, &rusnet_cmch, NULL);
  /* support no-color channels (+c channelmode) */
  Add_Binding("ircd-modechange", "c", 0, 0, (Function)&rusnet_mch_c, NULL);
  Add_Binding("ircd-check-message", "*", 0, 0, &rusnet_check_message, NULL);
  /* support extra restrictions on user (+b usermode, see RMODE/RLINE) */
/*
1. Rusnet umode +b (R-Mode) description
   No NICK change, no PRIVMSG/NOTICE to users except irc operators/services,
   no PRIVMSG/NOTICE to more than one nick at a time or to the #channel,
   no custom quit/part messages, no AWAY, no UMODE -b, no UMODE +x,
   no VERSION, no INFO, no LINKS, no TRACE, no STATS, no HELP, no LUSERS,
   no MOTD, penalty for all attempts, bigger penalti for ADMIN, TIME,
   no MODE, no getting +o/+v on channels, no JOIN on several channels
   at a time, bigger penalti for JOIN, no JOIN on &/! channels.
   Clonelimit for +b clients is independent from I:lines and is equal to 2.
 */
  Add_Binding("ircd-umodechange", "b", 0, 0, (Function)&rusnet_umch_b, NULL);
  Add_Binding("ircd-auth", "*", 0, 0, &rusnet_auth, NULL);
  Add_Binding("ircd-client-filter", "privmsg", 0, 0, &rusnet_check_msg, NULL);
  Add_Binding("ircd-client-filter", "notice", 0, 0, &rusnet_check_ntc, NULL);
  Add_Binding("ircd-client-filter", "nick", 0, 0, &rusnet_check_nick, NULL);
  Add_Binding("ircd-client-filter", "away", 0, 0, &rusnet_check_no_b, NULL);
  Add_Binding("ircd-client-filter", "umode", 0, 0, &rusnet_check_no_b, NULL);
  Add_Binding("ircd-client-filter", "version", 0, 0, &rusnet_check_no_b, NULL);
  Add_Binding("ircd-client-filter", "info", 0, 0, &rusnet_check_no_b, NULL);
  Add_Binding("ircd-client-filter", "links", 0, 0, &rusnet_check_no_b, NULL);
  Add_Binding("ircd-client-filter", "trace", 0, 0, &rusnet_check_no_b, NULL);
  Add_Binding("ircd-client-filter", "stats", 0, 0, &rusnet_check_no_b, NULL);
  Add_Binding("ircd-client-filter", "help", 0, 0, &rusnet_check_no_b, NULL);
  Add_Binding("ircd-client-filter", "lusers", 0, 0, &rusnet_check_no_b, NULL);
  Add_Binding("ircd-client-filter", "join", 0, 0, &rusnet_check_join, NULL);
  Add_Binding("ircd-client-filter", "admin", 0, 0, &rusnet_check_penalty, NULL);
  Add_Binding("ircd-client-filter", "time", 0, 0, &rusnet_check_penalty, NULL);
  Add_Binding("ircd-client-filter", "part", 0, 0, &rusnet_check_part, NULL);
  Add_Binding("ircd-client-filter", "quit", 0, 0, &rusnet_check_quit, NULL);
  Add_Binding("ircd-check-send", "002", 0, 0, &rusnet_ics_no_b, NULL); //RPL_YOURHOST
  Add_Binding("ircd-check-send", "003", 0, 0, &rusnet_ics_no_b, NULL); //RPL_CREATED
  Add_Binding("ircd-check-send", "004", 0, 0, &rusnet_ics_no_b, NULL); //RPL_MYINFO
  Add_Binding("ircd-check-send", "005", 0, 0, &rusnet_ics_no_b, NULL); //RPL_ISUPPORT
  Add_Binding("ircd-check-send", "372", 0, 0, &rusnet_ics_no_b, NULL); //RPL_MOTD
  Add_Binding("ircd-check-send", "375", 0, 0, &rusnet_ics_no_b, NULL); //RPL_MOTDSTART
  Add_Binding("ircd-check-send", "376", 0, 0, &rusnet_ics_motdend, NULL); //RPL_ENDOFMOTD
  Add_Binding("ircd-check-send", "422", 0, 0, &rusnet_ics_motdend, NULL); //ERR_NOMOTD
  /* support channel halfops (+h) */
  Add_Binding("ircd-whochar", "*", 0, 0, (Function)&iwc_rusnet, NULL);
  Add_Binding("ircd-modechange", "h", 0, 0, (Function)&rusnet_mch_h, NULL);
  Add_Binding("ircd-modechange", "l", 0, 0, (Function)&rusnet_mch_l, NULL);
  Add_Binding("ircd-modechange", "v", 0, 0, (Function)&rusnet_mch_v, NULL);
  Add_Binding("ircd-modechange", "b", 0, 0, (Function)&rusnet_mch_b, NULL);
  Add_Binding("ircd-modechange", "e", 0, 0, (Function)&rusnet_mch_e, NULL);
  Add_Binding("ircd-modechange", "I", 0, 0, (Function)&rusnet_mch_I, NULL);
  Add_Binding("ircd-modechange", "m", 0, 0, (Function)&rusnet_mch_m, NULL);
  Add_Binding("ircd-modechange", "n", 0, 0, (Function)&rusnet_mch_n, NULL);
  Add_Binding("ircd-modechange", "t", 0, 0, (Function)&rusnet_mch_t, NULL);
  Add_Binding("ircd-modechange", "k", 0, 0, (Function)&rusnet_mch_k, NULL);
  Add_Binding("ircd-modechange", "i", 0, 0, (Function)&rusnet_mch_i, NULL);
  Add_Binding("ircd-client-filter", "topic", 0, 0, &rusnet_check_topic, NULL);
  Add_Binding("ircd-client-filter", "kick", 0, 0, &rusnet_check_kick, NULL);
  /* stats k, e, r for above */
  Add_Binding ("ircd-stats-reply", "k", 0, 0, (Function)&rusnet_stats_k, NULL);
  Add_Binding ("ircd-stats-reply", "e", 0, 0, (Function)&rusnet_stats_e, NULL);
  Add_Binding ("ircd-stats-reply", "r", 0, 0, (Function)&rusnet_stats_r, NULL);
  /* tweak ircd-version-string so rusnet-ircd recognize we are compatible */
  if (GetVariable("ircd-version-string", VARIABLE_CONSTANT, &ptr))
  {
    char *str = ptr;			/* it's really not constant */
    if (str[6] == '0' && str[7] >= '0') /* we have 02110000.... there */
      str[6] = '1', str[7] = '5';	/* say it's rusnet-ircd 1.5.x */
  }
  // FIXME: tweak RPL_VERSION ?
  Add_Binding("ircd-isupport", "*", 0, 0, (Function)&rusnet_isupport, NULL);
  /* add commands for services */
  Add_Binding("ircd-client-cmd", "nickserv", 0, 0, &rusnet_nickserv_cb, NULL);
  Add_Binding("ircd-client-cmd", "chanserv", 0, 0, &rusnet_chanserv_cb, NULL);
  Add_Binding("ircd-client-cmd", "memoserv", 0, 0, &rusnet_memoserv_cb, NULL);
  Add_Binding("ircd-client-cmd", "operserv", 0, 0, &rusnet_operserv_cb, NULL);
  Send_Signal(I_MODULE, "ircd*", S_FLUSH); /* inform modules about changes */
  return (&module_signal);
}
#else /* RUSNET_COMPILE */
SigFunction ModuleInit (char *args)
{
  ERROR("ircd-rusnet was disabled at compile time, sorry.");
  return (NULL);
}
#endif
