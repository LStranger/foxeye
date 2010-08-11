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
 * This file is part of FoxEye's source: charset conversion API
 */

#ifndef	_CONVERSION_H
#define	_CONVERSION_H	1
#ifdef HAVE_ICONV

conversion_t *Get_Conversion (const char *);
void Free_Conversion (conversion_t *);
conversion_t *Clone_Conversion (conversion_t *);
const char *Conversion_Charset (conversion_t *);
size_t Do_Conversion (conversion_t *, char **, size_t, const char *, size_t);
size_t Undo_Conversion (conversion_t *, char **, size_t, const char *, size_t);

#endif
#endif
