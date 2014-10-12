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
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _UI_H
#define _UI_H 1

enum {
  T_WINNAME,			/* select window name for next packet */
  T_WINACT,			/* select name and activate */
  T_OFFSET,			/* set offset <val> for text (0 - autoshift) */
  T_PRIVTEXT,			/* private/highlighted text */
  T_GROUPTEXT,			/* group/public text */
  T_INFO,			/* info text */
  T_ADDLIST,			/* add people list */
  T_DELLIST,			/* delete people list */
  T_SCROLL,			/* shift offset by <val> lines */
  T_GET,			/* get lines from <val1+val2> up to <val1> */
  T_HEADER,			/* set header for window */
  T_TARGET,			/* change window target */
  T_HISTORY,			/* saved input (start <val> is max size) */
  T_INPUT,			/* put <arg> in input line */
  T_PROMPT,			/* set prompt for window input */
  T_ASK,			/* asked for new input with prompt <arg> */
  T_CLOSE,			/* close window */
  T_FRAGMENT			/* it's fragment of packet, to be continued */
};

#define UI_PKT_LEN 2048

struct ui_pkt {
  unsigned short typelen;	/* type << 11 + len & 0x7ff */
  unsigned char buf[UI_PKT_LEN];
};

#endif
