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

#ifndef USTUN_H_
#define USTUN_H_

#ifdef SOURCE_ustun
char remoteIP[20], localIP[20];
int mode;
#else
extern char remoteIP[20], localIP[20];
extern int mode;
#endif

/**
 * Print an help for this program
 */
void printHelp(void);

/**
 * Print the version of this program
 */
void printVersion(void);

/**
 * Check if the given IP is valid
 *
 * @param char *ipAddr       the given IP to check
 * @return int               0 if valid, -1 if invalid, -2 if not IP
 */
int isValidIP(char *ipAddr);

/**
 * Manage the command line parameters
 *
 * @param int argc           the number of the parameters in the command line
 * @param char **argv        the command line parameters
 */
void handleOptions(int argc, char **argv);

/**
 * Create the tunnel device
 */
int createTUN(void);

/**
 * Start the program as daemon
 */
void daemonize(void);

#endif // USTUN_H_

