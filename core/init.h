/*
 * Copyright (C) 1999-2002  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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

#ifndef INIT_C

	/* public part */
typedef char bool;
#define ASK		(1<<1)			/* ask-yes, ask-no */
#define CAN_ASK		(1<<2)			/* allow above two */

WHERE bool O_MAKEFILES		INITVAL(FALSE);
WHERE bool O_TESTCONF		INITVAL(FALSE);
WHERE bool O_DEFAULTCONF	INITVAL(FALSE);
WHERE bool O_GENERATECONF	INITVAL(FALSE);
WHERE bool O_WAIT		INITVAL(FALSE);

WHERE short O_DLEVEL		INITVAL(0);
WHERE char *Config		INITVAL(NULL);
WHERE char *RunPath		INITVAL(NULL);
WHERE char *BindResult		INITVAL(NULL);

WHERE time_t StartTime;

WHERE char DateString[13]	INITVAL("");	/* "%e %b %H:%M" */
WHERE time_t Time;

#define ScriptFunction(a) int a (const char *args)
int RegisterFunction (const char *, int (*)(const char *), const char *);
int UnregisterFunction (const char *);
int RegisterInteger (const char *, long int *);
int RegisterBoolean (const char *, bool *);
int UnregisterInteger (const char *);
int RegisterString (const char *, void *, size_t, int);
int UnregisterString (const char *);

char *SetFormat (const char *, char *);		/* name, new value */
int Save_Formats (void);
short *FloodType (const char *);

int RunBinding (BINDING *, const uchar *, char *, char *, int, char *);
int Config_Exec (const char *, const char *);
bool Confirm (char *, bool);

	/* core internal part */
void init (void);				/* [re]init functions */
char *IFInit_DCC (void);
char *IFInit_Users (void);
char *IFInit_Sheduler (void);

void Status_Interfaces (INTERFACE *);		/* for .status (dispatcher.c) */
void Status_Sheduler (INTERFACE *);		/* the same (sheduler.c) */
void Status_Users (INTERFACE *);		/* the same (userc.c) */

#ifndef DISPATCHER_C
# define Command(a,b,c)		int b(const char *);
#ifdef __INIT_C
# define Bool(a,b,c)		bool b = c;
# define Integer(a,b,c)		long int b = c;
# define String(a,b,c)		char b[STRING] = c;
# define Flood(a,b,c)
# define Format(a,b)		char format_##a[FORMATMAX] = b;
#else /* __INIT_C */
# define Bool(a,b,c)		extern bool b;
# define Integer(a,b,c)		extern long int b;
# define String(a,b,c)		extern char b[STRING];
# define Flood(a,b,c)
# define Format(a,b)		extern char format_##a[FORMATMAX];
#endif
#endif /* ifndef DISPATCHER_C */
#else /* ifndef INIT_C */
# define Command(a,b,c)		RegisterFunction (a, &b, c);
# define Bool(a,b,c)		RegisterBoolean (a, &b);
# define Integer(a,b,c)		RegisterInteger (a, &b);
# define String(a,b,c)		RegisterString (a, b, STRING, 0);
# define Flood(a,b,c)		_add_fl (#a, b, c);
# define Format(a,b)		_add_fmt (#a, format_##a);
#endif /* ifndef INIT_C */
#ifndef DISPATCHER_C
String  ("nick", Nick, "")			/* default nick and botnetnick */
String  ("my-hostname", hostname, "")
String  ("locale", locale, "")
String	("charset", Charset, "")		/* used by couple of modules */
String  ("listfile", Listfile, "listfile")
String  ("incoming-path", dnload_dir, "")
Integer	("dcc-turbo", dcc_turbo, 1)
Integer	("dcc-blocksize", dcc_blksize, 4096)
Integer	("dccget-maxsize", dcc_getmax, 1000000)
Integer	("dcc-resume-min", resume_min, 10000)
Integer	("dcc-resume-timeout", resume_timeout, 120)
Integer	("dcc-start-timeout", dcc_timeout, 120)
Integer ("ident-timeout", ident_timeout, 60)
Bool	("dcc-get", dcc_get, TRUE|ASK|CAN_ASK)
Bool	("dcc-resume", dcc_resume, TRUE|ASK|CAN_ASK)
Bool	("dcc-overwrite", dcc_overwrite, TRUE|CAN_ASK)
Flood   (dcc, 20, 5)
Integer ("max-dcc", max_dcc, 50)
Bool    ("protect-telnet", drop_unknown, TRUE)
Integer ("reserved-port", port_files, 0)
Command ("port", FE_port, "[-b] port")
/* Bool    ("show-motd", motdon, TRUE) */
String  ("motd", motd, "/home/andrej/foxeye/motd")
/* Bool    ("rotate", rotate, TRUE)
Command ("logfile", FE_logfile, "mode filename")
String  ("logrotate-path", logs_pattern, "%$.1") */
Integer ("cache-time", cache_time, 300)
/* Integer ("cache-size", cache_size, 1024) */
String  ("wtmpfile", Wtmp, "Wtmp")
Integer ("wtmps", wtmps, 4)
String	("formatsfile", FormatsFile, "")
Command ("module", FE_module, "name")		/* must be last :) */
#include "formats.default"
#undef Command
#undef Bool
#undef Integer
#undef String
#undef Flood
#undef Format
#endif /* ifndef DISPATCHER_C */
