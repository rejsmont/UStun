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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "incs/common.h"
#include "incs/logger.h"
#include "incs/clist.h"
#include "incs/filter.h"
#include "incs/state.h"

/**
 * Add a new conntrack to the list, managing the concurrent
 * access using semaphores.
 *
 * @param struct conntrack *entry    the new entry
 */
void addConntrack(struct conntrack *entry)
{
  struct cList *element = NULL;
  struct conntrack *entry1 = NULL;
  bool found = FALSE;

  entry->lastChange = time(NULL);
  sem_wait(&mutex);

  if(conntracks == NULL) // due to huge optimization by the compiler, it may be, that conntracks by the first insert is NULL
    conntracks = createCList();

  foreachCList(element, conntracks)
  {
    entry1 = (struct conntrack*) element->data;
    if(entry1 != NULL)
    {
      if((memcmp(&entry1->srcIP, &entry->srcIP, sizeof(struct in6_addr)) == 0) &&
         (memcmp(&entry1->dstIP, &entry->dstIP, sizeof(struct in6_addr)) == 0) &&
         (entry1->proto == entry->proto) &&
         (entry1->dstPort == entry->dstPort) &&
         (entry1->srcPort == entry->srcPort))
      {
        found = TRUE;
        break;
      }
    }
  }
// Just add the connection if it is not present yet
  if(found == FALSE)
    addToCList(conntracks, entry);

  sem_post(&mutex);
}

/**
 * Change the state of a connection, managing the concurrent
 * access using semaphores.
 *
 * @param struct conntrack *entry    the entry to be changed
 */
void modifyConntrack(struct conntrack *entry)
{
  struct cList *element = NULL;
  struct conntrack *entry1 = NULL;

  entry->lastChange = time(NULL);
  sem_wait(&mutex);

  foreachCList(element, conntracks)
  {
    entry1 = (struct conntrack*) element->data;
    if(entry1 != NULL)
    {
      if((memcmp(&entry1->srcIP, &entry->dstIP, sizeof(struct in6_addr)) == 0) &&
         (memcmp(&entry1->dstIP, &entry->srcIP, sizeof(struct in6_addr)) == 0) &&
         (entry1->proto == entry->proto) &&
         (entry1->dstPort == entry->srcPort) &&
         (entry1->srcPort == entry->dstPort))
      {
        entry1->state = entry->state;
        break;
      }
    }
  }

  sem_post(&mutex);
}

/**
 * Change the state of a connection, managing the concurrent
 * access using semaphores.
 * This function searches the conntrack in the reversed order
 * as modifyConntrak()
 *
 * @param struct conntrack *entry    the entry to be changed
 */
void modifyConntrackRev(struct conntrack *entry)
{
  struct cList *element = NULL;
  struct conntrack *entry1 = NULL;

  entry->lastChange = time(NULL);
  sem_wait(&mutex);

  foreachCList(element, conntracks)
  {
    entry1 = (struct conntrack*) element->data;
    if(entry1 != NULL)
    {
      if((memcmp(&entry1->srcIP, &entry->srcIP, sizeof(struct in6_addr)) == 0) &&
         (memcmp(&entry1->dstIP, &entry->dstIP, sizeof(struct in6_addr)) == 0) &&
         (entry1->proto == entry->proto) &&
         (entry1->dstPort == entry->dstPort) &&
         (entry1->srcPort == entry->srcPort))
      {
        entry1->state = entry->state;
        break;
      }
    }
  }

  sem_post(&mutex);
}

/**
 * Delete a conntrack from the list, managing the concurrent
 * access using semaphores.
 *
 * @param struct conntrack *entry    the entry to be deleted
 */
void deleteConntrack(struct conntrack *entry)
{
  struct cList *element = NULL;
  struct conntrack *entry1 = NULL;
  uint8_t found = 0;

  sem_wait(&mutex);

  foreachCList(element, conntracks)
  {
    entry1 = (struct conntrack*) element->data;
    if(entry1 != NULL)
    {
      if((memcmp(&entry1->srcIP, &entry->dstIP, sizeof(struct in6_addr)) == 0) &&
         (memcmp(&entry1->dstIP, &entry->srcIP, sizeof(struct in6_addr)) == 0) &&
         (entry1->proto == entry->proto) &&
         (entry1->dstPort == entry->srcPort) &&
         (entry1->srcPort == entry->dstPort))
      {
        found = 1;
        break;
      }
    }
  }
  if(found)
    conntracks = deleteFromCList(conntracks, element);

  sem_post(&mutex);
}

/**
 * Delete a conntrack from the list, managing the concurrent
 * access using semaphores.
 * This function searches the conntrack in the reversed order
 * as deleteConntrak()
 *
 * @param struct conntrack *entry    the entry to be deleted
 */
void deleteConntrackRev(struct conntrack *entry)
{
  struct cList *element = NULL;
  struct conntrack *entry1 = NULL;
  uint8_t found = 0;

  sem_wait(&mutex);

  foreachCList(element, conntracks)
  {
    entry1 = (struct conntrack*) element->data;
    if(entry1 != NULL)
    {
      if((memcmp(&entry1->srcIP, &entry->srcIP, sizeof(struct in6_addr)) == 0) &&
         (memcmp(&entry1->dstIP, &entry->dstIP, sizeof(struct in6_addr)) == 0) &&
         (entry1->proto == entry->proto) &&
         (entry1->dstPort == entry->dstPort) &&
         (entry1->srcPort == entry->srcPort))
      {
        found = 1;
        break;
      }
    }
  }
  if(found)
    conntracks = deleteFromCList(conntracks, element);

  sem_post(&mutex);
}

/**
 * Return the count of all conntracks in memory
 *
 * @return int                       the count of conntracks
 */
int getCountConntracks()
{
  struct cList *element = NULL;
  int count = 0;

  if(conntracks != NULL)
    foreachCList(element, conntracks)
      if(element->data != NULL)
        count++;

  return(count);
}

/**
 * Print the conntrack table
 */
void dumpConntracks()
{
  struct cList *element = NULL;
  struct conntrack *entry = NULL;
  char ipSrc[INET6_ADDRSTRLEN], ipDst[INET6_ADDRSTRLEN];

  foreachCList(element, conntracks)
  {
    entry = (struct conntrack*) element->data;
    if(entry != NULL)
    {
      inet_ntop(AF_INET6, &entry->srcIP, ipSrc, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &entry->dstIP, ipDst, INET6_ADDRSTRLEN);
      logger(LOG_DEBUG, "ConnTrack", "SrcIP: %s - DstIP: %s - SrcPort: %u - DstPort: %u - Proto: %u - Type: %u - Code: %u - State: %u",
            ipSrc, ipDst, entry->srcPort, entry->dstPort, entry->proto, entry->type, entry->code, entry->state);
    }
  }
}


/**
 * Flush all connection with state NEW older that MAX_CONNNEW seconds
 */
void flushConntracks()
{
  struct cList *element = NULL;
  struct conntrack *entry = NULL;
  time_t now = time(NULL);
  int nC = 0;

  sem_wait(&mutex);

  foreachCList(element, conntracks)
  {
    entry = (struct conntrack*) element->data;
    if(entry != NULL)
    {
      if((entry->state == STATE_NEW) && (now > (entry->lastChange + MAX_CONNNEW)))
      {
        conntracks = deleteFromCList(conntracks, element);
        nC++;
      }
    }
  }

  if(verboseLevel > 0)
    logger(LOG_INFO, "ConnTrack", "%d conntrack(s) flushed", nC);

  sem_post(&mutex);
}

/**
 * Analyze the packets and save the states (new, established, related)
 *
 * @param unsigned char *packet      The IP-packet to check (IPv6 in IPv4)
 * @param int length                 Total packet length
 * @param int direction              DIR_6TO4 or DIR_4TO6. The content of the packets are not the same
 * @return int                       0 if packet is allowed, 1 if it's to discard
 */
void state(unsigned char *packet, int length, int direction)
{
  int lenHeader = 0, l, testDirection;
  uint16_t control;
  uint8_t hasToFree = 0;
  struct conntrack *entry = NULL;
  char log[255];

  switch(direction)
  {
    case DIR_6TO4:
      lenHeader = 4 * (packet[0] & 0x0f);
    break;
    case DIR_4TO6:
      lenHeader = 4 * (packet[0] & 0x0f) + 4;
    break;
  }

  entry = malloc(sizeof(struct conntrack));
  memset(entry, 0, sizeof(struct conntrack));

  for(l = 0; l < 16; l++)
    entry->srcIP.s6_addr[l] = (unsigned int) packet[lenHeader + 8 + l];
  for(l = 0; l < 16; l++)
    entry->dstIP.s6_addr[l] = (unsigned int) packet[lenHeader + 24 + l];
  entry->proto = (int) *(packet + lenHeader + 6);

  switch(entry->proto)
  {
    case PKGTYPE_TCP:
      hasToFree = 1;
      entry->srcPort = getPort(packet + lenHeader + 40);
      entry->dstPort = getPort(packet + lenHeader + 42);
// 2 bytes for offset (4 bits), reserved (6 bits, always null) and control (6 bits)
      control = (((uint16_t) packet[lenHeader + 52]) << 8 | ((uint16_t) packet[lenHeader + 53])) & 0x3F;
      if(verboseLevel > 1)
      {
        bzero(log, 255);
        sprintf(log, "CTRL: %04X", control);
        if(((control & CTRL_URG) == CTRL_URG))
          strcat(log, " URG");
        if(((control & CTRL_ACK) == CTRL_ACK))
          strcat(log, " ACK");
        if(((control & CTRL_PSH) == CTRL_PSH))
          strcat(log, " PSH");
        if(((control & CTRL_RST) == CTRL_RST))
          strcat(log, " RST");
        if(((control & CTRL_SYN) == CTRL_SYN))
          strcat(log, " SYN");
        if(((control & CTRL_FIN) == CTRL_FIN))
          strcat(log, " FIN");
        logger(LOG_DEBUG, "ConnTrack", "%s", log);
      }
      if(((control & CTRL_SYN) == CTRL_SYN) && (direction == DIR_4TO6))
      {
        entry->state = STATE_NEW;
        addConntrack(entry);
        if(verboseLevel > 0)
          logger(LOG_DEBUG, "ConnTrack", "TCP NEW (%d in memory)", getCountConntracks());
        if(verboseLevel > 2)
          dumpConntracks();
        hasToFree = 0;
      }
      if(((control & CTRL_SYN) == CTRL_SYN) && ((control & CTRL_ACK) == CTRL_ACK) && (direction == DIR_6TO4))
      {
        entry->state = STATE_ESTABLISHED;
        modifyConntrack(entry);
        if(verboseLevel > 0)
          logger(LOG_DEBUG, "ConnTrack", "TCP ESTABLISHED (%d in memory)", getCountConntracks());
        if(verboseLevel > 2)
          dumpConntracks();
        hasToFree = 0;
      }
      if(((control & CTRL_SYN) == CTRL_SYN) && ((control & CTRL_ACK) == CTRL_ACK) && (direction == DIR_4TO6))
      {
        entry->state = STATE_ESTABLISHED;
        modifyConntrackRev(entry);
        if(verboseLevel > 0)
          logger(LOG_DEBUG, "ConnTrack", "TCP ESTABLISHED (%d in memory)", getCountConntracks());
        if(verboseLevel > 2)
          dumpConntracks();
        hasToFree = 0;
      }
      if(((control & CTRL_FIN) == CTRL_FIN) && (direction == DIR_4TO6))
      {
        deleteConntrackRev(entry);
        if(verboseLevel > 0)
          logger(LOG_DEBUG, "ConnTrack", "TCP FINISHED (%d in memory)", getCountConntracks());
        if(verboseLevel > 2)
          dumpConntracks();
      }
      if(((control & CTRL_RST) == CTRL_RST) && (direction == DIR_6TO4))
      {
// The client closed the connection (maybe nmap?)
        deleteConntrack(entry);
        if(verboseLevel > 0)
          logger(LOG_DEBUG, "ConnTrack", "TCP closed by client (%d in memory)", getCountConntracks());
        if(verboseLevel > 2)
          dumpConntracks();
      }
      related(packet, length, direction);
    break;
    case PKGTYPE_UDP:
      entry->srcPort = getPort(packet + lenHeader + 40);
      entry->dstPort = getPort(packet + lenHeader + 42);
      if(isMyIP(entry->srcIP))
        testDirection = DIR_6TO4;
      else
        testDirection = DIR_4TO6;
      if(direction == testDirection)
      {
        entry->state = STATE_NEW;
        addConntrack(entry);
        if(verboseLevel > 0)
          logger(LOG_DEBUG, "ConnTrack", "UDP query (%d in memory)", getCountConntracks());
        if(verboseLevel > 2)
          dumpConntracks();
      }
      else
      {
        deleteConntrack(entry);
        if(verboseLevel > 0)
          logger(LOG_DEBUG, "ConnTrack", "UDP answer (%d in memory)", getCountConntracks());
        if(verboseLevel > 2)
          dumpConntracks();
        hasToFree = 1;
      }
    break;
    case PKGTYPE_ICMP:
    case PKGTYPE_ICMPv6:
      entry->type = (uint8_t) packet[lenHeader + 40];
      entry->code = (uint8_t) packet[lenHeader + 41];
      if(entry->type == 0x80)
      {
        entry->state = STATE_NEW;
        addConntrack(entry);
        if(verboseLevel > 0)
          logger(LOG_DEBUG, "ConnTrack", "ICMP Request (%d in memory)", getCountConntracks());
        if(verboseLevel > 2)
          dumpConntracks();
      }
      else
      {
        deleteConntrack(entry);
        if(verboseLevel > 0)
          logger(LOG_DEBUG, "ConnTrack", "ICMP Reply (%d in memory)", getCountConntracks());
        if(verboseLevel > 2)
          dumpConntracks();
        hasToFree = 1;
      }
    break;
  }

  if(hasToFree)
    free(entry);

  if(time(NULL) > lastConnCheck + CONNCHECK_FREQ)
  {
    flushConntracks();
    if(verboseLevel > 0)
      logger(LOG_INFO, "ConnTrack", "Starting conntracks garbage collector");
    lastConnCheck = time(NULL);
  }
}

/**
 * Analyze the packets and check if a related port will be opened
 *
 * @param unsigned char *packet      The IP-packet to check (IPv6 in IPv4)
 * @param int length                 Total packet length
 * @param int direction              DIR_6TO4 or DIR_4TO6. The content of the packets are not the same
 * @return int                       0 if packet is allowed, 1 if it's to discard
 */
void related(unsigned char *packet, int length, int direction)
{
  uint8_t headerLen;
  int lenHeader = 0, startData, l;
  char *data, *p;
  int a, b, c, d, p1, p2, port;
  struct conntrack *entry = NULL;
  bool hasToFree = TRUE;

  switch(direction)
  {
    case DIR_6TO4:
      lenHeader = 4 * (packet[0] & 0x0f);
    break;
    case DIR_4TO6:
      lenHeader = 4 * (packet[0] & 0x0f) + 4;
    break;
  }

  entry = malloc(sizeof(struct conntrack));
  memset(entry, 0, sizeof(struct conntrack));
  for(l = 0; l < 16; l++)
    entry->srcIP.s6_addr[l] = (unsigned int) packet[lenHeader + 8 + l];
  for(l = 0; l < 16; l++)
    entry->dstIP.s6_addr[l] = (unsigned int) packet[lenHeader + 24 + l];
  entry->proto = (int) *(packet + lenHeader + 6);

  headerLen = (((((uint16_t) packet[lenHeader + 52]) << 8 | ((uint16_t) packet[lenHeader + 53])) & 0xF000) >> 12) * 4;
  startData = headerLen + 40;
  data = malloc(sizeof(char) * (length - startData + 1));
  bzero(data, length - startData + 1);
  for(l = 0; l < (length - startData); l++)
    data[l] = packet[lenHeader + startData + l];
  if(direction == DIR_4TO6)
  {
    if(strncasecmp(data, "PORT ", 5) == 0)
    {
      sscanf(data + 5, "%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &p1, &p2);
      port = p1 * 256 + p2;
      entry->srcPort = 20;
      entry->dstPort = port;
      entry->state = STATE_RELATED;
      addConntrack(entry);
      hasToFree = FALSE;
    }
  }
  else
  {
// 227 Entering Passive Mode (0,0,0,0,p1,p2)
    p = strcasestr(data, "passive mode (");
    if(p != NULL)
    {
      sscanf(p + strlen("passive mode "), "(%d,%d,%d,%d,%d,%d)", &a, &b, &c, &d, &p1, &p2);
      port = p1 * 256 + p2;
      entry->srcPort = 0;
      entry->dstPort = port;
      entry->state = STATE_RELATED;
      addConntrack(entry);
      hasToFree = FALSE;
    }
  }

  if(hasToFree == TRUE)
    free(entry);
  free(data);
}

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
uint8_t getPacketState(struct in6_addr srcIP, struct in6_addr dstIP, unsigned int proto, unsigned int srcPort, unsigned int dstPort)
{
  uint8_t state = STATE_NONE;
  struct cList *element = NULL;
  struct conntrack *entry = NULL;

  foreachCList(element, conntracks)
  {
    entry = (struct conntrack*) element->data;
    if(entry != NULL)
    {
      if((memcmp(&entry->srcIP, &dstIP, sizeof(struct in6_addr)) == 0) &&
         (memcmp(&entry->dstIP, &srcIP, sizeof(struct in6_addr)) == 0) &&
         (entry->proto == proto))
      {
        if(proto == PKGTYPE_ICMPv6)
          state = entry->state;
        else
        {
          if((entry->proto == PKGTYPE_TCP) && (entry->srcPort == 0) && (entry->dstPort == dstPort))
          { // first answer after a PASV (FTP) has a srcPort = 0
            entry->srcPort = srcPort;
            state = entry->state;
            break;
          }
          if((entry->srcPort == dstPort) && (entry->dstPort == srcPort))
          {
            state = entry->state;
            break;
          }
        }
      }
    }
  }

  return state;
}
