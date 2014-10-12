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
 *
 * This file is part of FoxEye's source: charset conversion API
 */

#ifndef	_CONVERSION_H
#define	_CONVERSION_H	1
#ifdef HAVE_ICONV

struct conversion_t *Get_Conversion (const char *) __attribute__((warn_unused_result));
void Free_Conversion (struct conversion_t *);
struct conversion_t *Clone_Conversion (struct conversion_t *) __attribute__((warn_unused_result));
const char *Conversion_Charset (struct conversion_t *);
size_t Do_Conversion (struct conversion_t *, char **, size_t, const char *, size_t *);
size_t Undo_Conversion (struct conversion_t *, char **, size_t, const char *, size_t *);

#endif
#endif
