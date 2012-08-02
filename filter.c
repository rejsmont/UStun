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
#include <ctype.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include "incs/common.h"
#include "incs/logger.h"
#include "incs/filter.h"
#include "incs/state.h"
#include <errno.h>

/**
 * Check if the connection is allowed
 *
 * @param unsigned char *packet   The IP-packet to check (IPv6 in IPv4)
 * @param int length              Total packet length
 * @param int direction           DIR_6TO4 or DIR_4TO6. The content of the packets are not the same
 * @return enum fwAction          What has the firewall to do with the packet?
 */
enum fwAction filter(unsigned char *packet, int length, int direction)
{
  int lenHeader = 0, l, k, proto;
  char *srcIP, *dstIP, *protoStr;
  uint16_t payloadLength;
  struct chain *checkChain, *input, *output;
  char log[4096], log1[255];
  struct in6_addr pkgSrcIP, pkgDstIP;
  int pkgSrcPort, pkgDstPort, pkgProto;

  input = &shmFW->chains[shmFW->input];
  output = &shmFW->chains[shmFW->output];
  
  switch(direction)
  {
    case DIR_4TO6:
      lenHeader = 4 * (packet[0] & 0x0f) + 4;
      checkChain = output;
    break;
    case DIR_6TO4:
    default:
      lenHeader = 4 * (packet[0] & 0x0f);
      checkChain = input;
    break;
  }

  if(verboseLevel > 0)
  {
    sem_wait(&mutex);
    srcIP = printIPv6(packet + lenHeader + 8);
    dstIP = printIPv6(packet + lenHeader + 24);
    proto = (int) *(packet + lenHeader + 6);
    protoStr = getProto(proto);
    flowLabel = ((0x000000ff & packet[lenHeader + 1]) << 16) + ((0x000000ff & packet[lenHeader + 2]) << 8) + (0x000000ff & packet[lenHeader + 3]);
    payloadLength = ((0x000000ff & packet[lenHeader + 4]) << 8) + (0x000000ff & packet[lenHeader + 5]);
    hopLimit = (0x000000ff & packet[lenHeader + 7]);
    logger(LOG_INFO, "filter", "Priority: %d\nFlow Label: %u\nPayload Length: %u\nNext Header: %d\nHop Limit: %d\nSrc Addr: %s\nDst Addr: %s\nSrc Port: %d\nDst Port: %d\nProto: %d (%s)",
              (packet[lenHeader] & 0x0F),
              flowLabel,
              payloadLength,
              (0x000000ff & packet[lenHeader + 6]),
              hopLimit,
              srcIP, dstIP,
              getPort(packet + lenHeader + 40),
              getPort(packet + lenHeader + 42),
              proto, protoStr);
    free(protoStr);
    free(srcIP);
    free(dstIP);
    if(proto == PKGTYPE_TCP)
      control = (((uint16_t) packet[lenHeader + 52]) << 8 | ((uint16_t) packet[lenHeader + 53])) & 0x3F;

    if(verboseLevel > 1)
    {
      logger(LOG_INFO, "filter", (direction == DIR_6TO4) ? "6to4" : "4to6");
      l = 0;
      while(l < length)
      {
        bzero(log, 4096);
        for(k = 0; (k < 16) && ((l + k) < length); k++)
        {
          bzero(log1, 255);
          sprintf(log1, "%02X ", packet[l + k]);
          strcat(log, log1);
        }
        for(; k < 16; k++)
          strcat(log, "   ");
        strcat(log, "\t");
        for(k = 0; (k < 16) && (l < length); k++, l++)
        {
          bzero(log1, 255);
          sprintf(log1, "%c ", isprint(packet[l]) ? packet[l] : '.');
          strcat(log, log1);
        }
        logger(LOG_INFO, "filter", "%s", log);
      }
    }
    sem_post(&mutex);
  }

  for(l = 0; l < 16; l++)
  {
    pkgSrcIP.s6_addr[l] = (unsigned int) packet[lenHeader + 8 + l];
    pkgDstIP.s6_addr[l] = (unsigned int) packet[lenHeader + 24 + l];
  }
  pkgSrcPort = getPort(packet + lenHeader + 40);
  pkgDstPort = getPort(packet + lenHeader + 42);
  pkgProto = (int) *(packet + lenHeader + 6);

  return checkPacket(length - lenHeader, pkgSrcIP, pkgDstIP, pkgSrcPort, pkgDstPort, pkgProto, checkChain);
}

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
enum fwAction checkPacket(int pkgLength, struct in6_addr srcIP, struct in6_addr dstIP, int srcPort, int dstPort, int proto, struct chain *chkChain)
{
  int l, k, matchPort;
  enum fwAction retAction, subRet;
  struct fwRule *rule;
  uint8_t state;

  if((strcmp(chkChain->name, "INPUT") == 0) || (strcmp(chkChain->name, "OUTPUT") == 0))
    retAction = chkChain->policy;
  else
    retAction = NONE;
  for(l = 0; l < chkChain->nRules; l++)
  {
    if(verboseLevel > 0)
      logger(LOG_DEBUG, "checkPacket", "Checking against rule %s/%d", chkChain->name, l);
    rule = &chkChain->rules[l];

// Checking state
    if(rule->states != STATE_NONE)
    {
      state = getPacketState(srcIP, dstIP, proto, srcPort, dstPort);
      if((state == STATE_NONE) || ((rule->states & state) != state))
        continue;
    }
// Checking proto
    if(rule->proto != PKGTYPE_ALL)
    {
      if(!(((rule->proto == proto) && (rule->notProto == 0)) ||
          ((rule->proto != proto) && (rule->notProto == 1))))
        continue;
    }
// Checking source address
    if(memcmp(&rule->srcAddr.ip, &in6addr_any, sizeof(in6addr_any)))
    {
      if(!(((isIPInNet(srcIP, rule->srcAddr.ip, rule->srcAddr.mask) == TRUE) && (rule->notSrcAddr == 0)) ||
           ((isIPInNet(srcIP, rule->srcAddr.ip, rule->srcAddr.mask) == FALSE) && (rule->notSrcAddr == 1))))
        continue;
    }
// Checking destination address
    if(memcmp(&rule->dstAddr.ip, &in6addr_any, sizeof(in6addr_any)))
    {
      if(!(((isIPInNet(dstIP, rule->dstAddr.ip, rule->dstAddr.mask) == TRUE) && (rule->notDstAddr == 0)) ||
           ((isIPInNet(dstIP, rule->dstAddr.ip, rule->dstAddr.mask) == FALSE) && (rule->notDstAddr == 1))))
        continue;
    }
// Checking Packet's type (only for proto == ICMPv6)
    if(proto == PKGTYPE_ICMPv6 && rule->type != 0)
    {
// On ICMPv6-Packets, the type is in the position of the first byte of srcPort
      if(!(((rule->type == ((srcPort & 0xFF00) >> 8)) && (rule->notType == 0)) ||
          ((rule->type != ((srcPort & 0xFF00) >> 8)) && (rule->notType == 1))))
        continue;
    }
// Checking source port
    if(rule->srcMultiPorts.nPorts != 0)
    {
      for(matchPort = k = 0; (k < rule->srcMultiPorts.nPorts) && (matchPort == 0); k++)
        if(((rule->srcMultiPorts.ports[k] == srcPort) && (rule->notMultiport == 0)) ||
           ((rule->srcMultiPorts.ports[k] != srcPort) && (rule->notMultiport == 1)))
          matchPort = 1;
      if(matchPort == 0)
        continue;
    }
    else
    {
      if(rule->srcPort != 0)
      {
        if(!(((rule->srcPort == srcPort) && (rule->notSrcPort == 0)) ||
            ((rule->srcPort != srcPort) && (rule->notSrcPort == 1))))
          continue;
      }
    }
// Checking destination port
    if(rule->dstMultiPorts.nPorts != 0)
    {
      for(matchPort = k = 0; (k < rule->dstMultiPorts.nPorts) && (matchPort == 0); k++)
      {
        if(((rule->dstMultiPorts.ports[k] == dstPort) && (rule->notMultiport == 0)) ||
           ((rule->dstMultiPorts.ports[k] != dstPort) && (rule->notMultiport == 1)))
          matchPort = 1;
      }
      if(matchPort == 0)
        continue;
    }
    else
    {
      if(rule->dstPort != 0)
      {
        if(!(((rule->dstPort == dstPort) && (rule->notDstPort == 0)) ||
            ((rule->dstPort != dstPort) && (rule->notDstPort == 1))))
          continue;
      }
    }

// Check complete, packet match against the rule, using the rule's action
// Updating nPackets and nBytes for the rule
    rule->nPackets++;
    rule->nBytes += pkgLength;
    
    // Has to jump to another chain? (eg: -A INPUT -j DROPIPS)
    if(rule->extraChainNumber != -1)
    {
      // Jumping to the selected chain
      subRet = checkPacket(pkgLength, srcIP, dstIP, srcPort, dstPort, proto, &shmFW->chains[rule->extraChainNumber]);
      if(subRet != NONE && subRet != LOG)
        return subRet;
      if(subRet == LOG)
      {
        logPacket(pkgLength, srcIP, dstIP, srcPort, dstPort, proto, rule->log);
        continue;
      }
      if(subRet == NONE)
        continue;
    }
    
    if(rule->action == LOG)
    {
      logPacket(pkgLength, srcIP, dstIP, srcPort, dstPort, proto, rule->log);
      continue;
    }
    
    if(rule->action == RETURN)
    {
      return NONE;
    }
    
    return rule->action;
  }

// If no rules in this chain matches, then update number of packets and bytes on the rule
// and use chain's policy (setted on function's start)
  chkChain->nPackets++;
  chkChain->nBytes += pkgLength;

  return retAction;
}

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
void logPacket(int pkgLength, struct in6_addr srcIP, struct in6_addr dstIP, int srcPort, int dstPort, int proto, struct logInfo log)
{
  char srcIPStr[INET6_ADDRSTRLEN], dstIPStr[INET6_ADDRSTRLEN], *protoStr;
  char controlStr[255];

  inet_ntop(AF_INET6, &srcIP, srcIPStr, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &dstIP, dstIPStr, INET6_ADDRSTRLEN);
  protoStr = getProto(proto);
  bzero(controlStr, 255);
  sprintf(controlStr, " CTRL: %04X", control);
  if(((control & CTRL_URG) == CTRL_URG))
    strcat(controlStr, " URG");
  if(((control & CTRL_ACK) == CTRL_ACK))
    strcat(controlStr, " ACK");
  if(((control & CTRL_PSH) == CTRL_PSH))
    strcat(controlStr, " PSH");
  if(((control & CTRL_RST) == CTRL_RST))
    strcat(controlStr, " RST");
  if(((control & CTRL_SYN) == CTRL_SYN))
    strcat(controlStr, " SYN");
  if(((control & CTRL_FIN) == CTRL_FIN))
    strcat(controlStr, " FIN");

  logger(log.level, (strlen(log.prefix) != 0) ? log.prefix : devname,
         "TUNNEL=%s->%s SRC=%s DST=%s LEN=%d HOPLIMIT=%d FLOWLBL=%d PROTO=%s SPT=%d DPT=%d%s",
          remoteIPStr, localIPStr,
          srcIPStr, dstIPStr,
          pkgLength,
          hopLimit, flowLabel,
          protoStr,
          srcPort, dstPort,
          controlStr
      );
  free(protoStr);
}

/**
 * Send a reject packet
 *
 * @param unsigned char *packet   The IP-packet to be rejected (IPv6 in IPv4)
 * @param void *args              The argument of the thread
 * @param int direction           DIR_6TO4 or DIR_4TO6. The content of the packets are not the same
 */
void sendReject(unsigned char *packet, void *args, int direction)
{
  unsigned char rejectPacket[60];
  int lenHeader = 0, proto, l, k, wrote;
  uint16_t checksum, checksumComplemented;
  uint32_t seqNo, ackNo;
  int sockv6, tun, remoteIP, tunMode;
  struct sockaddr_in remoteaddr;
  char log[4096], str[255];

  sockv6 = (*(struct threadArgs *)args).sockv6;
  tun = (*(struct threadArgs *)args).tun;
  remoteIP = (*(struct threadArgs *)args).remoteIP;
  tunMode = (*(struct threadArgs *)args).tunMode;
  memset(rejectPacket, 0, 60);

  switch(direction)
  {
    case DIR_6TO4:
      lenHeader = 4 * (packet[0] & 0x0f);
    break;
    case DIR_4TO6:
      lenHeader = 4 * (packet[0] & 0x0f) + 4;
    break;
  }
  proto = (int) *(packet + lenHeader + 6);

  rejectPacket[0] = 0x60;      // Version+Prio
  rejectPacket[1] = 0x00;      // Flow Label
  rejectPacket[2] = 0x00;
  rejectPacket[3] = 0x00;
  rejectPacket[4] = 0x00;      // Payload Length
  rejectPacket[5] = 0x14;
  rejectPacket[6] = proto;     // Next Header (Protocoll)
  rejectPacket[7] = 0x40;      // Hop Limit
// Source Address (= Destination Address of received packet)
  for(l = 0; l < 16; l++)
    rejectPacket[8 + l] = packet[lenHeader + 24 + l];
// Destination Address (= Source Address of received packet)
  for(l = 0; l < 16; l++)
    rejectPacket[24 + l] = packet[lenHeader + 8 + l];
// Source Port (= Destination Port of received packet)
  rejectPacket[40] = packet[lenHeader + 42];
  rejectPacket[41] = packet[lenHeader + 43];
// Destination Port (= Source Port of received packet)
  rejectPacket[42] = packet[lenHeader + 40];
  rejectPacket[43] = packet[lenHeader + 41];
  seqNo = ((packet[lenHeader + 44] & 0x00FF) << 24) |
          ((packet[lenHeader + 45] & 0x00FF) << 16) |
          ((packet[lenHeader + 46] & 0x00FF) << 8) |
          ((packet[lenHeader + 47] & 0x00FF));
  ackNo = ((packet[lenHeader + 48] & 0x00FF) << 24) |
          ((packet[lenHeader + 49] & 0x00FF) << 16) |
          ((packet[lenHeader + 50] & 0x00FF) << 8) |
          ((packet[lenHeader + 51] & 0x00FF));
// Sequence Number (= Ack Number of received packet)
  rejectPacket[44] = (ackNo & 0xFF000000) >> 24;
  rejectPacket[45] = (ackNo & 0x00FF0000) >> 16;
  rejectPacket[46] = (ackNo & 0x0000FF00) >> 8;
  rejectPacket[47] = (ackNo & 0x000000FF);
// Ack Number (= Sequence Number of received packet + 1)
  seqNo++;
  rejectPacket[48] = (seqNo & 0xFF000000) >> 24;
  rejectPacket[49] = (seqNo & 0x00FF0000) >> 16;
  rejectPacket[50] = (seqNo & 0x0000FF00) >> 8;
  rejectPacket[51] = (seqNo & 0x000000FF);
  rejectPacket[52] = 0x50;     // Offset, Reserved, Flags (ACK+RST)
  rejectPacket[53] = 0x14;
  rejectPacket[54] = 0x00;     // Window
  rejectPacket[55] = 0x00;

  checksum = 0;
  for(l = 8; l < 24; l += 2)                                  // Source Address
    checksum += (rejectPacket[l] << 8) | (rejectPacket[l + 1]);
  for(l = 24; l < 40; l += 2)                                 // Destination Address
    checksum += (rejectPacket[l] << 8) | (rejectPacket[l + 1]);
  checksum += 0x0017;                                         // TCPLen (PayloadLen + 0x03)
  checksum += proto;                                          // Next Header (Protocoll)
  checksum += (rejectPacket[40] << 8) | (rejectPacket[41]);   // Source Port
  checksum += (rejectPacket[42] << 8) | (rejectPacket[43]);   // Destination Port
  for(l = 44; l < 48; l += 2)                                 // Sequence Number
    checksum += (rejectPacket[l] << 8) | (rejectPacket[l + 1]);
  for(l = 48; l < 52; l += 2)                                 // Ack Number
    checksum += (rejectPacket[l] << 8) | (rejectPacket[l + 1]);
  checksum += 0x5014;                                         // Offset, Reserved, Flags (0x5014 by Reject)
  checksumComplemented = ~checksum;                           // Checksum should be sent als one's complement

  rejectPacket[56] = (checksumComplemented & 0xFF00) >> 8;
  rejectPacket[57] = (checksumComplemented & 0x00FF);

  rejectPacket[58] = 0x00;     // Urgent pointer
  rejectPacket[59] = 0x00;

  if(verboseLevel > 1)
  {
    sem_wait(&mutex);
    bzero(log, 4096);
    sprintf(log, "%s:\n", (direction == DIR_6TO4) ? "4to6" : "6to4"); // Inverted, due to send a response!!
    l = 0;
    while(l < (60)) // Reject packets are always 60 bytes long
    {
      bzero(str, 255);
      for(k = 0; (k < 16) && ((l + k) < (60)); k++)
      {
        sprintf(str, "%02X ", rejectPacket[l + k]);
        strcat(log, str);
      }
      for(; k < 16; k++)
        strcat(log, "   ");
      strcat(log, "\t");
      bzero(str, 255);
      for(k = 0; (k < 16) && (l < (60)); k++, l++)
      {
        sprintf(str, "%c ", isprint(rejectPacket[l]) ? rejectPacket[l] : '.');
        strcat(log, str);
      }
      strcat(log, "\n");
    }
    logger(LOG_INFO, "sendReject", "%s", log);
    sem_post(&mutex);
  }

// Sends the rejectPacket (Here are the direction inverted! We send answer)
  remoteaddr.sin_family = AF_INET;
  remoteaddr.sin_port = htons(IPPROTO_IPV6);
  bzero(&(remoteaddr.sin_zero), 8);
  switch(direction)
  {
    case DIR_6TO4:
      switch(tunMode)
      {
        case MODE_6TO4:
// Send packet directly to (IPv4)xx.xx.xx.xx other than default gw 192.88.99.1 when handing (IPv6)2002:xxxx:xxxx::/48 package
          if(*(short *)(&packet[(sizeof(struct tun_pi) + 24)]) == 0x0220)
            remoteaddr.sin_addr.s_addr = *(int *)(&packet[(sizeof(struct tun_pi) + 26)]);
        break;
// In ISATAP mode, IPv6 packages to /64 neighbours are send directly to their IPv4 address without relay
        case MODE_ISATAP:
          if(
              (*(int *)(&packet[(sizeof(struct tun_pi) + 24)]) == *(int *)(&packet[(sizeof(struct tun_pi) + 8)])) &&
              (*(int *)(&packet[(sizeof(struct tun_pi) + 28)]) == *(int *)(&packet[(sizeof(struct tun_pi) + 12)])) &&
              (*(int *)(&packet[(sizeof(struct tun_pi) + 32)]) == *(int *)(&packet[(sizeof(struct tun_pi) + 16)])) &&
              (*(int *)(&packet[(sizeof(struct tun_pi) + 16)]) == 0xfe5e0000)
            )
            remoteaddr.sin_addr.s_addr = *(int *)(&packet[(sizeof(struct tun_pi) + 36)]);
        break;
        case MODE_TUNNELBROKER:
        default:
// In Tunnelbroker mode the packets are send to the remote endpoint
          remoteaddr.sin_addr.s_addr = remoteIP;
        break;
      }
      wrote = sendto(sockv6, &rejectPacket, (60), 0, (struct sockaddr *)&remoteaddr, sizeof(struct sockaddr));
      logger(LOG_INFO, "4to6", "%d bytes", wrote);
    break;
    case DIR_4TO6:
      wrote = write(tun, &rejectPacket, (60));
      logger(LOG_INFO, "6to4", "%d bytes", wrote);
    break;
  }
}

/**
 * Allocate the shared memory for the firewall rules
 *
 * @return int                    0 if no error, -1 if errors
 */
int createRulesSpace(key_t shm_id)
{
  int l, k;
  struct chain *input, *output;

  // Create the segment.

  if((shmid = shmget(shm_id, sizeof(struct firewall), IPC_CREAT | 0600)) < 0)
  {
    printf("Unable to create shared memory segment\n");
    return(-1);
  }
  // Now we attach the segment to our data space.
  if((shmFW = shmat(shmid, NULL, 0)) == (struct firewall *) -1)
  {
    printf("Unable to attach segment\n");
    return(-1);
  }

  // Clear all data
  memset(shmFW, 0, sizeof(struct firewall));
  for(l = 0; l < MAX_CHAINS_NUM; l++)
    for(k = 0; k < MAX_RULES_NUM; k++)
      shmFW->chains[l].rules[k].extraChainNumber = -1;
  shmFW->input = shmFW->nChains++;
  shmFW->output = shmFW->nChains++;
  input = &shmFW->chains[shmFW->input];
  output = &shmFW->chains[shmFW->output];
  strcpy(input->name, "INPUT");
  strcpy(output->name, "OUTPUT");
  // Set default policies (ACCEPT)
  input->policy = output->policy = ACCEPT;
  // No rules (yet)
  input->nRules = output->nRules = 0;

  logger(LOG_INFO, "main", "Allocated %d bytes for firewall rules", sizeof(struct firewall));

  return 0;
}

/**
 * Free the allocated shared memory for the firewall rules
 *
 * @return int                    0 if no error, -1 if errors
 */
int freeRulesSpace()
{
  return(shmdt(shmFW));
}

/**
 * Destroy the allocated shared memory for the firewall rules
 *
 * @return int                    0 if no error, -1 if errors
 */
int destroyRulesSpace()
{
  if(freeRulesSpace() == 0)
  {
    return 0;
  }
  return -1;
}

/**
 * Get to from server allocated shared memory for the firewall rules
 *
 * @return int                    0 if no error, -1 if errors
 */
int bindToRulesSpace(key_t shm_id)
{
  // Create the segment.
  if((shmid = shmget(shm_id, sizeof(struct firewall), 0600)) < 0)
  {
    printf("Unable to get shared memory segment\n");
    return(-1);
  }

  // Now we attach the segment to our data space.
  if((shmFW = shmat(shmid, NULL, 0)) == (struct firewall *) -1)
  {
    printf("Unable to attach segment\n");
    return(-1);
  }
  return 0;
}
