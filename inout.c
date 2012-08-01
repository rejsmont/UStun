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
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <pthread.h>
#include <netinet/in.h>
#include "incs/common.h"
#include "incs/logger.h"
#include "incs/ustun.h"
#include "incs/inout.h"
#include "incs/filter.h"
#include "incs/state.h"

/**
 * Manage the incoming data over the IPv6 tunnel
 *
 * @param void *args              Connection's data
 */
void io6to4(void *args)
{
  int sockv6, tun, ret, res, remoteIP, leniphead, tunMode, fd, max;
  unsigned char bufsock[4096];
  char *ipStr1, *ipStr2;
  struct tun_pi pi = {0, htons(ETH_P_IPV6)};
  fd_set fdSet;
  bool stop = FALSE;

  sockv6 = (*(struct threadArgs *)args).sockv6;
  tun = (*(struct threadArgs *)args).tun;
  remoteIP = (*(struct threadArgs *)args).remoteIP;
  tunMode = (*(struct threadArgs *)args).tunMode;
  fd = (*(struct threadArgs *)args).fd;

  logger(LOG_INFO, "6to4", "starting thread");
  while(stop == FALSE)
  {
    FD_ZERO(&fdSet);
    FD_SET(sockv6, &fdSet);
    FD_SET(fd, &fdSet);
    if(fd > sockv6)
      max = fd;
    else
      max = sockv6;

    if(select(max + 1, &fdSet, NULL, NULL, NULL) >= 0)
    {
      if(FD_ISSET(fd, &fdSet))
      {
        FD_CLR(fd, &fdSet);
        res = read(fd, bufsock, sizeof(bufsock));
        if(res > 0 && bufsock[0] == 'C')
        {
          logger(LOG_INFO, "6to4", "received stop signal");
          stop = TRUE;
        }
      }
      if(FD_ISSET(sockv6, &fdSet))
      {
        FD_CLR(sockv6, &fdSet);
        if((res = recv(sockv6, bufsock, sizeof(bufsock), 0)) < 0)
        {
          if(res != -1) // Nonblocking Socket. If no data read, recv will return -1
            logger(LOG_NOTICE, "6to4", "socket error");
          continue;
        }
        leniphead = 4 * (bufsock[0] & 0x0f);
        if(leniphead > 60 || leniphead < 20)
        {
          logger(LOG_NOTICE, "6to4", "IPv4 header too long");
          continue;
        }
        switch(tunMode)
        {
          case MODE_TUNNELBROKER:
// Only accept packets with source IPv4 address the same as tunnel server's
            if(*(int *)(&bufsock[12]) != remoteIP)
            {
              ipStr1 = printIPv4(*(int *)(&bufsock[12]));
              ipStr2 = printIPv4(remoteIP);
              logger(LOG_NOTICE, "6to4", "Drop package from source IPv4 %s not the relay server %s", ipStr1, ipStr2);
              free(ipStr1);
              free(ipStr2);
              continue;
            }
          break;
          case MODE_ISATAP:
// In ISATAP mode, we should accept package (IPv6) prefix:0:5efe:xx.xx.xx.xx in (IPv4) xx.xx.xx.xx
            if((*(int *)(&bufsock[12]) != remoteIP ) &&
               ((*(int *)(&bufsock[(leniphead + 16)]) != 0xfe5e0000) ||
                (*(int *)(&bufsock[12]) != *(int *)(&bufsock[leniphead + 20]))
               )
              )
            {
              ipStr1 = printIPv4(*(int *)(&bufsock[12]));
              logger(LOG_NOTICE, "6to4", "Drop package from source IPv4 %s do not corresponds its IPv6 address", ipStr1);
              free(ipStr1);
              continue;
            }
          break;
          case MODE_6TO4:
            if((*(int *)(&bufsock[12])!=remoteIP))
            {
// In 6to4 mode, (IPv6) 2002:xxxx:xxxx::/48 in (IPv4) xx.xx.xx.xx should be accepted
              if(*(short *)(&bufsock[(leniphead + 8)]) != 0x0220)
              {
                ipStr1 = printIPv4(*(int *)(&bufsock[12]));
                logger(LOG_NOTICE, "6to4", "Drop package from source IPv4 %s do not corresponds its IPv6 address", ipStr1);
                free(ipStr1);
                continue;
              }
              else if((*(int *)(&bufsock[12])) != (*(int *)(&bufsock[(leniphead + 10)])))
              {
                ipStr1 = printIPv4(*(int *)(&bufsock[12]));
                logger(LOG_NOTICE, "6to4", "Drop package from source IPv4 %s do not corresponds its IPv6 address", ipStr1);
                free(ipStr1);
              }
            }
          break;
        }

// Do packet filter
        switch(filter(bufsock, res, DIR_6TO4))
        {
          case DROP:
            continue;
          break;
          case REJECT:
            sendReject(bufsock, args, DIR_6TO4);
            continue;
          break;
          default:
          break;
        }

// Check packet state
        state(bufsock, res, DIR_6TO4);

        ret = res - leniphead;
        memcpy(&bufsock[leniphead-sizeof(struct tun_pi)], &pi, sizeof(struct tun_pi));
        ret = write(tun, &bufsock[leniphead-sizeof(struct tun_pi)], ret + sizeof(struct tun_pi));
        if(verboseLevel > 1)
          logger(LOG_INFO, "6to4", "%d/%d bytes", res, ret);
      }
    }
  }

  logger(LOG_INFO, "6to4", "exiting thread");
}

/**
 * Manage the outgoing data over the IPv6 tunnel
 *
 * @param void *args              Connection's data
 */
void io4to6(void *args)
{
  int sockv6, tun, ret, res, remoteIP, tunMode, fd, max;
  unsigned char buftun[4096];
  struct sockaddr_in remoteaddr;
  fd_set fdSet;
  bool stop = FALSE;

  sockv6 = (*(struct threadArgs *)args).sockv6;
  tun = (*(struct threadArgs *)args).tun;
  remoteIP = (*(struct threadArgs *)args).remoteIP;
  tunMode = (*(struct threadArgs *)args).tunMode;
  fd = (*(struct threadArgs *)args).fd;

  remoteaddr.sin_family = AF_INET;
  remoteaddr.sin_port = htons(IPPROTO_IPV6);
  bzero(&(remoteaddr.sin_zero), 8);

  logger(LOG_INFO, "4to6", "starting thread");
  while(stop == FALSE)
  {
    FD_ZERO(&fdSet);
    FD_SET(tun, &fdSet);
    FD_SET(fd, &fdSet);
    if(fd > tun)
      max = fd;
    else
      max = tun;

    if(select(max + 1, &fdSet, NULL, NULL, NULL) >= 0)
    {
      if(FD_ISSET(fd, &fdSet))
      {
        FD_CLR(fd, &fdSet);
        res = read(fd, buftun, sizeof(buftun));
        if(res > 0 && buftun[0] == 'C')
        {
          logger(LOG_INFO, "6to4", "received stop signal");
          stop = TRUE;
        }
      }
      if(FD_ISSET(tun, &fdSet))
      {
        FD_CLR(tun, &fdSet);
        if((ret = read(tun, buftun, sizeof(buftun))) < 0)
        {
          if(ret != -1) // Nonblocking Socket. If no data read, read will return -1
            logger(LOG_NOTICE, "4to6", "Tunnel error");
          continue;
        }
        if(ret != -1)
        {
// Do packet filter
          switch(filter(buftun, ret, DIR_4TO6))
          {
            case DROP:
              continue;
            break;
            case REJECT:
              sendReject(buftun, args, DIR_4TO6);
              continue;
            break;
            default:
            break;
          }

// Check packet state
          state(buftun, ret, DIR_4TO6);

          switch(tunMode)
          {
            case MODE_6TO4:
// Send packet directly to (IPv4)xx.xx.xx.xx other than default gw 192.88.99.1 when handing (IPv6)2002:xxxx:xxxx::/48 package
              if(*(short *)(&buftun[(sizeof(struct tun_pi) + 24)]) == 0x0220)
                remoteaddr.sin_addr.s_addr = *(int *)(&buftun[(sizeof(struct tun_pi) + 26)]);
            break;
// In ISATAP mode, IPv6 packages to /64 neighbours are send directly to their IPv4 address without relay
            case MODE_ISATAP:
              if(
                  (*(int *)(&buftun[(sizeof(struct tun_pi) + 24)]) == *(int *)(&buftun[(sizeof(struct tun_pi) + 8)])) &&
                  (*(int *)(&buftun[(sizeof(struct tun_pi) + 28)]) == *(int *)(&buftun[(sizeof(struct tun_pi) + 12)])) &&
                  (*(int *)(&buftun[(sizeof(struct tun_pi) + 32)]) == *(int *)(&buftun[(sizeof(struct tun_pi) + 16)])) &&
                  (*(int *)(&buftun[(sizeof(struct tun_pi) + 16)]) == 0xfe5e0000)
                )
                remoteaddr.sin_addr.s_addr = *(int *)(&buftun[(sizeof(struct tun_pi) + 36)]);
            break;
            case MODE_TUNNELBROKER:
            default:
// In Tunnelbroker mode the packets are send to the remote endpoint
              remoteaddr.sin_addr.s_addr = remoteIP;
            break;
          }
// Send the data to the calculated IPv4
          res = sendto(sockv6, &buftun[sizeof(struct tun_pi)], ret, 0, (struct sockaddr *)&remoteaddr, sizeof(struct sockaddr));
          if(verboseLevel > 1)
            logger(LOG_INFO, "4to6", "%d/%d bytes", ret ,res);
        }
      }
    }
  }

  logger(LOG_INFO, "4to6", "exiting thread");
}
