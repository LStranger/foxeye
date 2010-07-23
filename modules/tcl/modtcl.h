/*
 * Copyright (C) 1999-2010  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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

#ifndef _FE_TCL_H
#define _FE_TCL_H 1

#ifdef HAVE_TCL
# include "tcl.h"
#endif

#ifdef HAVE_TCL8X
# define TCLARGS Tcl_Obj *CONST		/* last argument of command */
  //int ArgInteger (Tcl_Interp *, Tcl_Obj *);
# define ArgString Tcl_GetStringFromObj
#else
# define TCLARGS char *
# define ArgInteger(i,a) atoi(a)
# define ArgString(a,b) a, *(b) = safe_strlen (a)
#endif

//void ResultInteger (Tcl_Interp *, int);
//void ResultString (Tcl_Interp *, char *, size_t);

#endif
