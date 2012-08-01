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

#ifndef USCTRL_H_
#define USCTRL_H_

#ifdef SOURCE_usctrl
enum ctrlCommand command;
int param;
#else
extern enum ctrlCommand command;
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
 * Manage the command line parameters
 *
 * @param int argc           the number of the parameters in the command line
 * @param char **argv        the command line parameters
 */
void handleOptions(int argc, char **argv);

/**
 * Send a command to the ustun-module
 *
 * @param char *param        the parameter (or NULL if there are no parameters)
 */
void sendCommand(char *param);

#endif // USCTRL_H_

