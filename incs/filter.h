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

#ifndef FILTER_H_
#define FILTER_H_

#define SHM_ID                    6666
#define MAX_RULES_NUM             250 // max. 100 Firewall rules
#define MAX_CHAINS_NUM            50  // max. 20 chains

#define PKGTYPE_ALL               0   // All protocols
#define PKGTYPE_ICMP              1   // Internet Control Message Protocol (ICMP)
#define PKGTYPE_TCP               6   // Transmission Control Protocol (TCP)
#define PKGTYPE_UDP               17  // User Datagram Protocol (UDP)
#define PKGTYPE_RH                43  // Routing header
#define PKGTYPE_FH                44  // Fragment header
#define PKGTYPE_ICMPv6            58  // Internet Control Message Protocol version 6 (ICMPv6)
#define PKGTYPE_NONE              59  // nothing; this is the final header
#define PKGTYPE_DST_OPT_HDR       60  // Destination Options header
#define PKGTYPE_OSPF              89  // Open Shortest Path First (OSPF)

enum fwAction
{
  NONE, ACCEPT, REJECT, DROP, LOG, RETURN
};

struct ipv6addr
{
  struct in6_addr ip;
  struct in6_addr mask;
};

struct multiport
{
  int ports[15];
  uint8_t nPorts;
};

struct logInfo
{
  char prefix[30];
  uint8_t level;
};

struct fwRule
{
  int srcPort, dstPort;
  struct multiport srcMultiPorts, dstMultiPorts;
  struct ipv6addr srcAddr, dstAddr;
  int proto;
  int type;
  uint8_t states;
  int extraChainNumber;
  enum fwAction action;
  unsigned long nPackets;
  unsigned long long nBytes;
  char comment[255];
  struct logInfo log;
  unsigned int notSrcPort : 1;
  unsigned int notDstPort : 1;
  unsigned int notSrcAddr : 1;
  unsigned int notDstAddr : 1;
  unsigned int notMultiport : 1;
  unsigned int notProto : 1;
  unsigned int notType : 1;
};

struct chain
{
  char name[255];
  enum fwAction policy;
  int nRules;
  struct fwRule rules[MAX_RULES_NUM];
  unsigned long nPackets;
  unsigned long long nBytes;
};

struct firewall
{
  struct chain chains[MAX_CHAINS_NUM];
  struct chain *input, *output;
  uint8_t nChains;
};

#ifdef SOURCE_filter
int shmid;
struct firewall *shmFW;
uint32_t flowLabel;
uint8_t hopLimit;
uint16_t control;
#else
extern struct firewall *shmFW;
#endif

#define DIR_6TO4                  0
#define DIR_4TO6                  1

/**
 * Check if the connection is allowed
 *
 * @param unsigned char *packet   The IP-packet to check (IPv6 in IPv4)
 * @param int length              Total packet length
 * @param int direction           DIR_6TO4 or DIR_4TO6. The content of the packets are not the same
 * @return enum fwAction          What has the firewall to do with the packet?
 */
enum fwAction filter(unsigned char *packet, int length, int direction);

/**
 * Check the given packet against the given chain
 *
 * @param int pkgLength           The length of the packet
 * @param struct in6_addr srcIP   The source address of the packet
 * @param struct in6_addr dstIP   The destination address of the packet
 * @param int srcPort             The source port of the packet
 * @param int dstPort             The destination port of the packet
 * @param int proto               The protocol of the packet
 * @param struct chain *chkChain  The chain against that the packet has to be checked
 * @return enum fwAction          What has the firewall to do with the packet?
 */
enum fwAction checkPacket(int pkgLength, struct in6_addr srcIP, struct in6_addr dstIP, int srcPort, int dstPort, int proto, struct chain *chkChain);

/**
 * Log the given packet to syslog
 *
 * @param int pkgLength           The length of the packet
 * @param struct in6_addr srcIP   The source address of the packet
 * @param struct in6_addr dstIP   The destination address of the packet
 * @param int srcPort             The source port of the packet
 * @param int dstPort             The destination port of the packet
 * @param int proto               The protocol of the packet
 * @param struct logInfo log      The log information
 */
void logPacket(int pkgLength, struct in6_addr srcIP, struct in6_addr dstIP, int srcPort, int dstPort, int proto, struct logInfo log);

/**
 * Send a reject packet
 *
 * @param unsigned char *packet   The IP-packet to be rejected (IPv6 in IPv4)
 * @param void *args              The argument of the thread
 * @param int direction           DIR_6TO4 or DIR_4TO6. The content of the packets are not the same
 */
void sendReject(unsigned char *packet, void *args, int direction);

/**
 * Allocate the shared memory for the firewall rules
 *
 * @return int                    0 if no error, -1 if errors
 */
int createRulesSpace(key_t shm_id);

/**
 * Free the allocated shared memory for the firewall rules
 *
 * @return int                    0 if no error, -1 if errors
 */
int freeRulesSpace();

/**
 * Destroy the allocated shared memory for the firewall rules
 *
 * @return int                    0 if no error, -1 if errors
 */
int destroyRulesSpace();

/**
 * Get to from server allocated shared memory for the firewall rules
 *
 * @return int                    0 if no error, -1 if errors
 */
int bindToRulesSpace(key_t shm_id);

#endif // FILTER_H_

