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

#ifndef STATE_H_
#define STATE_H_

#include <semaphore.h>

#define CTRL_URG                  0x20
#define CTRL_ACK                  0x10
#define CTRL_PSH                  0x08
#define CTRL_RST                  0x04
#define CTRL_SYN                  0x02
#define CTRL_FIN                  0x01

#define STATE_NONE                0x00
#define STATE_NEW                 0x01
#define STATE_ESTABLISHED         0x02
#define STATE_RELATED             0x04

#define MAX_CONNNEW               1800   // all connection in state NEW older than 30 minutes will be flushed
#define CONNCHECK_FREQ              60   // connection status will be checked every minute

struct conntrack
{
  unsigned int srcPort, dstPort;
  struct in6_addr srcIP, dstIP;
  unsigned int proto;
  uint8_t type, code;
  uint8_t state;
  time_t lastChange;
};

#ifdef SOURCE_state
struct cList *conntracks;
sem_t mutex;
time_t lastConnCheck = 0;
#else
extern struct cList *conntracks;
extern sem_t mutex;
#endif

/**
 * Add a new conntrack to the list, managing the concurrent
 * access using semaphores.
 *
 * @param struct conntrack *entry    the new entry
 */
void addConntrack(struct conntrack *entry);

/**
 * Change the state of a connection, managing the concurrent
 * access using semaphores.
 *
 * @param struct conntrack *entry    the entry to be changed
 */
void modifyConntrack(struct conntrack *entry);

/**
 * Change the state of a connection, managing the concurrent
 * access using semaphores.
 * This function searches the conntrack in the reversed order
 * as modifyConntrak()
 *
 * @param struct conntrack *entry    the entry to be changed
 */
void modifyConntrackRev(struct conntrack *entry);

/**
 * Delete a conntrack from the list, managing the concurrent
 * access using semaphores.
 *
 * @param struct conntrack *entry    the entry to be deleted
 */
void deleteConntrack(struct conntrack *entry);

/**
 * Delete a conntrack from the list, managing the concurrent
 * access using semaphores.
 * This function searches the conntrack in the reversed order
 * as deleteConntrak()
 *
 * @param struct conntrack *entry    the entry to be deleted
 */
void deleteConntrackRev(struct conntrack *entry);

/**
 * Return the count of all conntracks in memory
 *
 * @return int                       the count of conntracks
 */
int getCountConntracks(void);

/**
 * Print the conntrack table
 */
void dumpConntracks(void);

/**
 * Flush all connection with state NEW older that MAX_CONNNEW seconds
 */
void flushConntracks(void);

/**
 * Analyze the packets and save the states (new, established, related)
 *
 * @param unsigned char *packet      The IP-packet to check (IPv6 in IPv4)
 * @param int length                 Total packet length
 * @param int direction              DIR_6TO4 or DIR_4TO6. The content of the packets are not the same
 * @return int                       0 if packet is allowed, 1 if it's to discard
 */
void state(unsigned char *packet, int length, int direction);

/**
 * Analyze the packets and check if a related port will be opened
 *
 * @param unsigned char *packet      The IP-packet to check (IPv6 in IPv4)
 * @param int length                 Total packet length
 * @param int direction              DIR_6TO4 or DIR_4TO6. The content of the packets are not the same
 * @return int                       0 if packet is allowed, 1 if it's to discard
 */
void related(unsigned char *packet, int length, int direction);

/**
 * Return the state of the packet, based on the given data
 *
 * @param struct in6_addr srcIP      The source IP
 * @param struct in6_addr dstIP      The destination IP
 * @param unsigned int proto         The protocol
 * @param unsigned int srcPort       The source port
 * @param unsigned int dstPort       The destination port
 * @return uint8_t                   The state of the current packet
 */
uint8_t getPacketState(struct in6_addr srcIP, struct in6_addr dstIP, unsigned int proto, unsigned int srcPort, unsigned int dstPort);

#endif // STATE_H_

