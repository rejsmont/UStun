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

#ifndef COMMANDS_H_
#define COMMANDS_H_

#ifdef SOURCE_commands
#else
#endif

/**
 * Check if the given string is a number
 *
 * @return int                    1 if the given string is numeric
 */
int isNumeric(char *s);

/**
 * Get the rule description from user's given parameters
 *
 * @return struct fwRule*         the rule description or NULL on errors
 */
struct fwRule* getRuleDescription(void);

/**
 * Append a rule to the given chain
 */
int cmdAppend(void);

/**
 * Delete a rule from the given chain
 */
int cmdDelete(void);

/**
 * Insert a rule to the given chain at the given position
 */
int cmdInsert(void);

/**
 * Replace a rule from the given chain
 */
int cmdReplace(void);

/**
 * List the rules (if given, just from given chain)
 */
int cmdList(void);

/**
 * Flush all rules (if given, just from given chain)
 */
int cmdFlush(void);

/**
 * Zeros the paket count (if given, just from given chain)
 */
int cmdZero(void);

/**
 * Set the policy for the given chain
 */
int cmdPolicy(void);

/**
 * Create a new chain
 */
int cmdNewChain(void);

/**
 * Delete chain(s)
 */
int cmdDeleteChain(void);

/**
 * Delete a given chain
 */
int cmdDeleteChainX(void);

/**
 * Rename the given chain
 */
int cmdRenameChain(void);

#endif // COMMANDS_H_
