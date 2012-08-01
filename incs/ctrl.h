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

#ifndef CTRL_H_
#define CTRL_H_

#define SHM_CTRLID                6667

enum ctrlCommand
{
  NOCMD, GETINFO, SETVERBOSE, QUIT, GETCONNTRACKS, FLUSHCONNTRACKS, DELETECONNTRACK
};

struct ctrlMem
{
  enum ctrlCommand cmd;
  char param[255];
  uint8_t executeCmd : 1;
  uint8_t validAnswer : 1;
  uint8_t lastAnswer : 1;
  uint8_t gotAnswer : 1;
  char answer[1024];
};

#ifdef SOURCE_ctrl
int shmctrlid;
struct ctrlMem *shmCtrl;
#else
extern struct ctrlMem *shmCtrl;
#endif

/**
 * Manage the control thread
 *
 * @param void *args              Connection's data
 */
void ctrl(void *args);

/**
 * Send the answer to the control program and
 * wait until it got it
 */
void sendAnswer(void);

/**
 * Free the allocated shared memory for the control interface
 *
 * @return int                    0 if no error, -1 if errors
 */
int freeCtrlSpace();

/**
 * Destroy the allocated shared memory for the control interface
 *
 * @return int                    0 if no error, -1 if errors
 */
int destroyCtrlSpace();

/**
 * Get to from server allocated shared memory for the control interface
 *
 * @return int                    0 if no error, -1 if errors
 */
int bindToCtrlSpace(void);

#endif // CTRL_H_

