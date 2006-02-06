/*
 * Copyright (C) 2005  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 */

#ifndef _UI_H
#define _UI_H 1

enum {
  T_WINNAME,			/* set name for next text */
  T_WINACT,			/* set name and activate */
  T_OFFSET,			/* set offset for next text */
  T_PRIVTEXT,			/* private/highlighted text */
  T_GROUPTEXT,			/* group/public text */
  T_INFO,			/* info text */
  T_ADDLIST,			/* add people list */
  T_DELLIST,			/* delete people list */
  T_DOWN,			/* scroll down <arg> lines */
  T_UP,				/* scroll up <arg> lines */
  T_HEADER,			/* set header for window */
  T_TARGET,			/* change window target */
  T_INPUT,			/* put <arg> in input line */
  T_PROMPT,			/* set prompt for window input */
  T_ASK,			/* asked for new input with prompt <arg> */
  T_CLOSE			/* close window/client */
};

#define UI_PKT_LEN 2048

typedef struct {
  unsigned short typelen;	/* type << 11 + len & 0x7ff */
  unsigned char buf[UI_PKT_LEN];
} ui_pkt;

#endif