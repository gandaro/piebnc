/************************************************************************
 *   psybnc, tools/chkdns.c
 *   Copyright (C) 2001 the most psychoid  and
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

/**
 * This program gets compiled, if c-ares is available. This is a hack to
 * not have to rewrite the 'autoconf' part of psyBNC too much and will
 * need to be replaced one day by configure and friends.
 */

#include <ares.h>

int main(int argc, char **argv)
{
    ares_channel resolver;
    ares_init(&resolver);
    return 0;
}
