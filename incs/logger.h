/*******************************************************************************
*    Userspace Tunnel with Firewall 1.0.                                       *
*    Copyright (C) 2011-averyfarwaydate Luca Bertoncello                       *
*    Hartigstrasse, 12 - 01127 Dresden Deutschland                             *
*    E-Mail: lucabert@lucabert.de, lucabert@lucabert.com                       *
*    http://www.lucabert.de/  http://www.lucabert.com/                         *
*                                                                              *
*    Based on the idea from: http://code.google.com/p/tb-tun/                  *
*                                                                              *
*    This program is free software; you can redistribute it and/or modify      *
*    it under the terms of the GNU General Public License as published by      *
*    the Free Software Foundation; version 2 of the License.                   *
*                                                                              *
*    This program is distributed in the hope that it will be useful,           *
*    but WITHOUT ANY WARRANTY; without even the implied warranty of            *
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
*    GNU General Public License for more details.                              *
*                                                                              *
*    You should have received a copy of the GNU General Public License         *
*    along with this program; if not, write to the Free Software               *
*    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA *
*******************************************************************************/

#ifndef LOGGER_H_
#define LOGGER_H_

#include <syslog.h>

enum logDestination
{
  SYSLOG, STDERR
};

#ifdef SOURCE_logger
enum logDestination logTo;
#else
extern enum logDestination logTo;
#endif

/**
 * Log to the configured log subsystem (stderr, syslog)
 *
 * @param int priority            the syslog priority of the message
 * @param const char *prefix      the prefix
 * @param const char *format      the format of the string (printf-format)
 */
void logger(int priority, const char *prefix, const char *format, ...);

/**
 * Initialize the logger subsystem
 */
void initLogger(void);

/**
 * Close the logger subsystem
 */
void closeLogger(void);

#endif // LOGGER_H_

