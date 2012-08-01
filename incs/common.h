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

#ifndef COMMON_H_
#define COMMON_H_

#define CURRENTVERSION          "0.3-20110605"

#define DEFAULT_PIDFILE         "/var/run/ustun.pid"
#define MODE_6TO4               0
#define MODE_TUNNELBROKER       1
#define MODE_ISATAP             2

typedef enum _bool { FALSE, TRUE} bool;

#ifdef SOURCE_common
int verboseLevel, hasToStop;
char localIPStr[INET_ADDRSTRLEN], remoteIPStr[INET_ADDRSTRLEN];
char devname[255];
int pipe6to4[2], pipe4to6[2];
int tun, sockv6;
char pidFile[255];
#else
extern int verboseLevel, hasToStop;
extern char localIPStr[INET_ADDRSTRLEN], remoteIPStr[INET_ADDRSTRLEN];
extern char devname[255];
extern int pipe6to4[2], pipe4to6[2];
extern int tun, sockv6;
extern char pidFile[255];
#endif

struct threadArgs
{
  int sockv6;
  int tun;
  int localIP, remoteIP;
  int tunMode;
  int fd;
};

/**
 * Return the given IPv4 address in dotted notation
 *
 * @param int ip             the given IPv4
 * @return char*             the IPv4 in dotted notation
 */
char* printIPv4(int ip);

/**
 * Return the given IPv6 address in dotted notation
 *
 * @param unsigned char *ip  the given IPv6 (16 bytes)
 * @return char*             the IPv6 in dotted notation
 */
char* printIPv6(unsigned char *ip);

/**
 * Return the mask for the given network
 *
 * @param struct in6_addr net   the network
 * @return int                  the mask
 */
int getIPv6Mask(struct in6_addr net);

/**
 * Return the network for the given mask
 *
 * @param int mask              the mask
 * @return struct in6_addr      the network
 */
struct in6_addr getIPv6Network(int mask);

/**
 * Return the given amount converted in K, M or G
 *
 * @param unsigned long long amount      the amount
 * @return char*                         the converted amount as string
 */
char *printAmount(unsigned long long amount);

/**
 * Return the port from the given 2 bytes
 *
 * @param unsigned char *p   the given port from IPv6 header (2 bytes)
 * @return int               the port
 */
int getPort(unsigned char *p);

/**
 * Return the given protocol as string
 *
 * @param int proto          the protocol
 * @return char*             the protocol as string
 */
char *getProto(int proto);

/**
 * Test if the give IP is part of the given network (baseIP/mask)
 *
 * @param struct in6_addr testIP     the IP to check
 * @param struct in6_addr baseIP     the base of the mask
 * @param struct in6_addr mask       the network mask
 * @return bool                      TRUE if the given IP is part of the given network, FALSE if not
 */
bool isIPInNet(struct in6_addr testIP, struct in6_addr baseIP, struct in6_addr mask);

/**
 * Stop the program and free the allocated memory
 */
void stopUSTun(void);

/**
 * Return if the given IPv6 address belongs to the local IPv6 interface
 *
 * @param struct in6_addr ip         the IP to check
 * @return bool                      TRUE if the given IP belongs to the local IPv6 interface, FALSE if not
 */
bool isMyIP(struct in6_addr ip);

#endif // COMMON_H_
