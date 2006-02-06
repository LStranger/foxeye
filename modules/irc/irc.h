/*
 * Copyright (C) 2005-2006  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * internal functions for message queueing
 */

/* msgs.c -> irc.c */
char *irc_mynick (char *);
void irc_lcs (char *, INTERFACE *, const char *, size_t); /* buf,pmsgout,nick */

/* irc.c -> msgs.c */
int irc_privmsgin (INTERFACE *, char *, char*, char *, int, int, int,
			char *(*) (char *, const char *, size_t));
void irc_privmsgout (INTERFACE *, int); /* just run stack */
int irc_privmsgout_default (INTERFACE *, REQUEST *);
void irc_privmsgout_cancel (INTERFACE *, char *);
int irc_privmsgout_count (INTERFACE *);

void irc_privmsgreg (void);
void irc_privmsgunreg (void);
