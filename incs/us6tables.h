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

#ifndef US6TABLES_H_
#define US6TABLES_H_

enum commands
{
  NOCMD, APPEND, DELETE, INSERT, REPLACE, LIST, FLUSH, ZERO, POLICY, NEWCHAIN, DELETECHAIN, RENAMECHAIN
};

enum options
{
  PROTO, SOURCE, DESTINATION, NUMERIC, VERBOSE, LINENO, EXACT
};

#ifdef SOURCE_us6tables
enum commands command;
enum options option[10]; // max 10 options
int nOptions;
int paramIndex;
char **prgArgv;
int prgArgc;
char chain[20];
#else
extern enum commands command;
extern enum options option[10];
extern int nOptions;
extern int paramIndex;
extern char chain[20];
extern char **prgArgv;
extern int prgArgc;
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

#endif // US6TABLES_H_

