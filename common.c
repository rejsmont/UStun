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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/types.h>
#include "incs/filter.h"
#include "incs/clist.h"
#include "incs/state.h"
#include "incs/logger.h"
#include "incs/common.h"

/**
 * Return the given IPv4 address in dotted notation
 *
 * @param int ip             the given IPv4
 * @return char*             the IPv4 in dotted notation
 */
char* printIPv4(int ip)
{
  char ipStr[INET_ADDRSTRLEN];

  bzero(ipStr, INET_ADDRSTRLEN);

  sprintf(ipStr, "%d.%d.%d.%d",
    (0x000000ff & ip),
    (0x0000ff00 & ip)>>8,
    (0x00ff0000 & ip)>>16,
    (0xff000000 & ip)>>24);
  return strdup(ipStr);
}

/**
 * Return the given IPv6 address in dotted notation
 *
 * @param unsigned char *ip  the given IPv6 (16 bytes)
 * @return char*             the IPv6 in dotted notation
 */
char* printIPv6(unsigned char *ip)
{
  char ipStr[INET6_ADDRSTRLEN];
  struct in6_addr ip6;
  int l;

  bzero(ipStr, INET6_ADDRSTRLEN);

  for(l = 0; l < 16; l++)
    ip6.s6_addr[l] = (unsigned int) ip[l];

  inet_ntop(AF_INET6, &ip6, ipStr, INET6_ADDRSTRLEN);
  return strdup(ipStr);
}

/**
 * Return the mask for the given network
 *
 * @param struct in6_addr net   the network
 * @return int                  the mask
 */
int getIPv6Mask(struct in6_addr net)
{
  int mask = 0;
  int l, k;
  __be32 m;

  for(l = 0; l < 4; l++)
  {
    m = 0x80000000;
    for(k = 0; k < 32; k++)
    {
      if(net.s6_addr32[l] & m)
        mask++;
      m >>= 1;
    }
  }
  return mask;
}

/**
 * Return the network for the given mask
 *
 * @param int mask              the mask
 * @return struct in6_addr      the network
 */
struct in6_addr getIPv6Network(int mask)
{
  int l, k, i;
  __be32 m;
  struct in6_addr net;

  memset(&net, 0, sizeof(struct in6_addr));
  for(i = l = 0; (l < 16) && (i < mask); l++)
  {
    m = 0x80;
    for(k = 0; (k < 8) && (i < mask); k++)
    {
      if(i < mask)
        net.s6_addr[l] |= m;
      i++;
      m >>= 1;
    }
  }

  return net;
}

/**
 * Return the given amount converted in K, M or G
 *
 * @param unsigned long long amount      the amount
 * @return char*                         the converted amount as string
 */
char *printAmount(unsigned long long amount)
{
  char unit[2], str[6];
  int div;

  bzero(unit, 2);
  div = 1;
  if(amount > 1024 * 10)
  {
    unit[0] = 'K';
    div = 1024;
  }
  if(amount > 1024 * 1024 * 10)
  {
    unit[0] = 'M';
    div = 1024 * 1024;
  }
  if(amount > 1024 * 1024 * 1024)
  {
    unit[0] = 'G';
    div = 1024 * 1024 * 1024;
  }
  sprintf(str, "%llu%s", amount / div, unit);
  return(strdup(str));
}

/**
 * Return the port from the given 2 bytes
 *
 * @param unsigned char *p   the given port from IPv6 header (2 bytes)
 * @return int               the port
 */
int getPort(unsigned char *p)
{
  return ((0x000000ff & p[0]) << 8) + (0x000000ff & p[1]);
}

/**
 * Return the given protocol as string
 *
 * @param int proto          the protocol
 * @return char*             the protocol as string
 */
char *getProto(int proto)
{
  switch(proto)
  {
    case PKGTYPE_ALL:
      return(strdup("all"));
    break;
    case PKGTYPE_ICMP:
      return(strdup("icmp"));
    break;
    case PKGTYPE_TCP:
      return(strdup("tcp"));
    break;
    case PKGTYPE_UDP:
      return(strdup("udp"));
    break;
    case PKGTYPE_RH:
      return(strdup("RH"));
    break;
    case PKGTYPE_FH:
      return(strdup("FH"));
    break;
    case PKGTYPE_ICMPv6:
      return(strdup("icmpv6"));
    break;
    case PKGTYPE_NONE:
      return(strdup("none"));
    break;
    case PKGTYPE_DST_OPT_HDR:
      return(strdup("HDT"));
    break;
    case PKGTYPE_OSPF:
      return(strdup("OSPF"));
    break;
    default:
      return(strdup(""));
    break;
  }
}

/**
 * Test if the give IP is part of the given network (baseIP/mask)
 *
 * @param struct in6_addr testIP     the IP to check
 * @param struct in6_addr baseIP     the base of the mask
 * @param struct in6_addr mask       the network mask
 * @return bool                      TRUE if the given IP is part of the given network, FALSE if not
 */
bool isIPInNet(struct in6_addr testIP, struct in6_addr baseIP, struct in6_addr mask)
{
  int l;

  for(l = 0; l < 4; l++)
    if((testIP.s6_addr32[l] & mask.s6_addr32[l]) != (baseIP.s6_addr32[l] & mask.s6_addr32[l]))
      return FALSE;
  return TRUE;
}

/**
 * Stop the program and free the allocated memory
 */
void stopUSTun()
{
  logger(LOG_INFO, "USTun", "Received stop signal");
  if(write(pipe4to6[1], "C", 1) != 1)
    logger(LOG_ALERT, "USTun", "Unable to stop thread");
  if(write(pipe6to4[1], "C", 1) != 1)
    logger(LOG_ALERT, "USTun", "Unable to stop thread");
  destroyRulesSpace();
  destroyCList(conntracks);
  sem_destroy(&mutex);
  hasToStop = 1;
  close(tun);
  close(sockv6);
  if(logTo != STDERR)
    unlink(pidFile);
}

/**
 * Return if the given IPv6 address belongs to the local IPv6 interface
 *
 * @param struct in6_addr ip         the IP to check
 * @return bool                      TRUE if the given IP belongs to the local IPv6 interface, FALSE if not
 */
bool isMyIP(struct in6_addr ip)
{
  struct ifaddrs *ifAddrStruct = NULL;
  struct ifaddrs *ifa = NULL;
  bool ret = FALSE;

  getifaddrs(&ifAddrStruct);
  for(ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
  {
    if(strcmp(ifa->ifa_name, devname) != 0)
      continue;
    if(ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET6)
    {
      if(memcmp(&ip, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr)) == 0)
        ret = TRUE;
    }
  }
  if(ifAddrStruct != NULL)
    freeifaddrs(ifAddrStruct);

  return(ret);
}
