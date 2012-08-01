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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include "incs/common.h"
#include "incs/logger.h"

/**
 * Log to the configured log subsystem (stderr, syslog)
 *
 * @param int priority            the syslog priority of the message
 * @param const char *prefix      the prefix
 * @param const char *format      the format of the string (printf-format)
 */
void logger(int priority, const char *prefix, const char *format, ...)
{
  va_list ap;
  char buf[4096];

  va_start(ap, format);
  vsnprintf(buf, sizeof(buf), format, ap);
  buf[sizeof(buf)-1] = '\0';
  if(logTo == SYSLOG)
    syslog(priority, "%s: %s", prefix, buf);
  else
    fprintf(stderr, "%s: %s\n", prefix, buf);
  va_end(ap);
}

/**
 * Initialize the logger subsystem
 */
void initLogger()
{
  if(logTo == SYSLOG)
    openlog("USTun", LOG_NDELAY, LOG_KERN);
}

/**
 * Close the logger subsystem
 */
void closeLogger()
{
  if(logTo == SYSLOG)
    closelog();
}
