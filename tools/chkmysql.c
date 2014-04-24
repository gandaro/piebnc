/************************************************************************
 *   psybnc, tools/chkmysql.c
 *   Copyright (C) 2011 the most psychoid  and
 *                      the cool lam3rz IRC Group, IRCnet
 *			http://www.psychoid.lam3rz.de
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* this program gets compiled, if mysql is supported. */

#include <stdio.h>
#include <stdlib.h>
#include <mysql.h>

int main()
{
    MYSQL mysql, *sock = NULL;
    unsigned int mysqltimeout = 2;
    mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, (const char *)&mysqltimeout);
    exit(0x0);
}
