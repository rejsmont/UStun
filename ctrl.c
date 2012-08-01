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
#include <time.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <sys/shm.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "incs/common.h"
#include "incs/logger.h"
#include "incs/ustun.h"
#include "incs/ctrl.h"
#include "incs/clist.h"
#include "incs/filter.h"
#include "incs/state.h"

/**
 * Manage the control thread
 *
 * @param void *args              Connection's data
 */
void ctrl(void *args)
{
  int sockv6, tun, localIP, remoteIP, tunMode, ct, l;
  char *ipStr, *protoStr;
  struct cList *element = NULL;
  struct conntrack *entry = NULL;
  char ipSrc[INET6_ADDRSTRLEN], ipDst[INET6_ADDRSTRLEN], st[20];
  bool found;
  struct tm *localTime;

  sockv6 = (*(struct threadArgs *)args).sockv6;
  tun = (*(struct threadArgs *)args).tun;
  localIP = (*(struct threadArgs *)args).localIP;
  remoteIP = (*(struct threadArgs *)args).remoteIP;
  tunMode = (*(struct threadArgs *)args).tunMode;

  if((shmctrlid = shmget(SHM_CTRLID, sizeof(struct ctrlMem), IPC_CREAT | 0600)) < 0)
  {
    printf("Unable to create shared memory segment\n");
    return;
  }

  // Now we attach the segment to our data space.
  if((shmCtrl = shmat(shmctrlid, NULL, 0)) == (struct ctrlMem *) -1)
  {
    printf("Unable to attach segment\n");
    return;
  }
  logger(LOG_INFO, "ctrl", "Allocated %d bytes for control interface", sizeof(struct ctrlMem));

  // Clear all data
  memset(shmCtrl, 0, sizeof(struct ctrlMem));

  logger(LOG_INFO, "ctrl", "starting thread");
  while(!hasToStop)
  {
    if(shmCtrl->executeCmd == 1)
    {
      switch(shmCtrl->cmd)
      {
        case GETINFO:
          sprintf(shmCtrl->answer, "TUN name is %s", devname);
          shmCtrl->lastAnswer = 0;
          sendAnswer();
          switch(tunMode)
          {
            case MODE_6TO4:
              sprintf(shmCtrl->answer, "TUN mode is 6to4");
            break;
            case MODE_TUNNELBROKER:
              sprintf(shmCtrl->answer, "TUN mode is tunnelbroker");
            break;
            case MODE_ISATAP:
              sprintf(shmCtrl->answer, "TUN mode is isatap");
            break;
            default:
            break;
          }
          shmCtrl->lastAnswer = 0;
          sendAnswer();
          sprintf(shmCtrl->answer, "IPv4 SOCK_RAW created: %d", sockv6);
          shmCtrl->lastAnswer = 0;
          sendAnswer();
          ipStr = printIPv4(localIP);
          sprintf(shmCtrl->answer, "Bind local IPv4 address: %s", ipStr);
          free(ipStr);
          shmCtrl->lastAnswer = 0;
          sendAnswer();
          ipStr = printIPv4(remoteIP);
          sprintf(shmCtrl->answer, "Using remote IPv4: %s", ipStr);
          free(ipStr);
          shmCtrl->lastAnswer = 0;
          sendAnswer();
          sprintf(shmCtrl->answer, "Verbose level set to %d", verboseLevel);
          shmCtrl->lastAnswer = 1;
          sendAnswer();
        break;
        case SETVERBOSE:
          verboseLevel = atoi(shmCtrl->param);
          sprintf(shmCtrl->answer, "Verbose level set to %d", verboseLevel);
          logger(LOG_INFO, "main", "Verbose level set to %d", verboseLevel);
          shmCtrl->lastAnswer = 1;
          sendAnswer();
        break;
        case QUIT:
          strcpy(shmCtrl->answer, "Stopping ustun");
          shmCtrl->lastAnswer = 1;
          sendAnswer();
          stopUSTun();
        break;
        case GETCONNTRACKS:
          sprintf(shmCtrl->answer, "Currently in memory:");
          shmCtrl->lastAnswer = 0;
          sendAnswer();
          if(conntracks == NULL) // due to huge optimization by the compiler, it may be, that conntracks by the first insert is NULL
            sprintf(shmCtrl->answer, "There are no connections");
          else
          {
            foreachCList(element, conntracks)
            {
              entry = (struct conntrack*) element->data;
              if(entry != NULL)
              {
                inet_ntop(AF_INET6, &entry->srcIP, ipSrc, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &entry->dstIP, ipDst, INET6_ADDRSTRLEN);
                bzero(st, 20);
                switch(entry->state)
                {
                  case STATE_NONE:
                    strcpy(st, "NONE");
                  break;
                  case STATE_NEW:
                    strcpy(st, "NEW");
                  break;
                  case STATE_ESTABLISHED:
                    strcpy(st, "ESTABLISHED");
                  break;
                  case STATE_RELATED:
                    strcpy(st, "RELATED");
                  break;
                }
                localTime = localtime(&entry->lastChange);
                protoStr = getProto(entry->proto);
                sprintf(shmCtrl->answer, "%4d-%02d-%02d %02d:%02d:%02d - SrcIP: %s - DstIP: %s - SrcPort: %u - DstPort: %u - Proto: %s - Type: %u - Code: %u - State: %s",
                      localTime->tm_year + 1900, localTime->tm_mon + 1, localTime->tm_mday, localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
                      ipSrc, ipDst, entry->srcPort, entry->dstPort, protoStr, entry->type, entry->code, st);
                shmCtrl->lastAnswer = 0;
                free(protoStr);
                sendAnswer();
              }
            }
            sprintf(shmCtrl->answer, "Total: %d", getCountConntracks());
          }
          shmCtrl->lastAnswer = 1;
          sendAnswer();
        break;
        case FLUSHCONNTRACKS:
          if(conntracks == NULL) // due to huge optimization by the compiler, it may be, that conntracks by the first insert is NULL
            sprintf(shmCtrl->answer, "There are no connections");
          else
          {
            sem_wait(&mutex);
            foreachCList(element, conntracks)
            {
              entry = (struct conntrack*) element->data;
              if(entry != NULL)
                conntracks = deleteFromCList(conntracks, element);
            }
            sem_post(&mutex);
            sprintf(shmCtrl->answer, "Connection table flushed");
          }
          shmCtrl->lastAnswer = 1;
          sendAnswer();
        break;
        case DELETECONNTRACK:
          ct = atoi(shmCtrl->param);
          if(conntracks == NULL) // due to huge optimization by the compiler, it may be, that conntracks by the first insert is NULL
            sprintf(shmCtrl->answer, "There are no connections");
          else
          {
            sem_wait(&mutex);
            found = FALSE;
            l = 0;
            foreachCList(element, conntracks)
            {
              entry = (struct conntrack*) element->data;
              if((entry != NULL) && (l == ct))
              {
                found = TRUE;
                break;
              }
              l++;
            }
            if(found != TRUE)
              sprintf(shmCtrl->answer, "Connection not found");
            else
            {
              conntracks = deleteFromCList(conntracks, element);
              sprintf(shmCtrl->answer, "Connection %d deleted", ct);
            }
            sem_post(&mutex);
          }
          shmCtrl->lastAnswer = 1;
          sendAnswer();
        break;
        default:
          strcpy(shmCtrl->answer, "Unknown command");
          shmCtrl->lastAnswer = 1;
          sendAnswer();
        break;
      }
      // Clear all data
      memset(shmCtrl, 0, sizeof(struct ctrlMem));
    }
    usleep(2000);
  }

  destroyCtrlSpace();
  logger(LOG_INFO, "ctrl", "exiting thread");
}

/**
 * Send the answer to the control program and
 * wait until it got it
 */
void sendAnswer()
{
  shmCtrl->gotAnswer = 0;
  shmCtrl->validAnswer = 1;
  while(shmCtrl->gotAnswer == 0)
    usleep(250);
  shmCtrl->gotAnswer = shmCtrl->validAnswer = 0;
  bzero(shmCtrl->answer, 1024);
}

/**
 * Free the allocated shared memory for the control interface
 *
 * @return int                    0 if no error, -1 if errors
 */
int freeCtrlSpace()
{
  return(shmdt(shmCtrl));
}

/**
 * Destroy the allocated shared memory for the control interface
 *
 * @return int                    0 if no error, -1 if errors
 */
int destroyCtrlSpace()
{
  logger(LOG_INFO, "ctrl", "Freeing %d bytes for control interface", sizeof(struct ctrlMem));
  if(freeCtrlSpace() == 0)
    return shmctl(shmctrlid, IPC_RMID, 0);
  return -1;
}

/**
 * Get to from server allocated shared memory for the control interface
 *
 * @return int                    0 if no error, -1 if errors
 */
int bindToCtrlSpace()
{
  // Create the segment.
  if((shmctrlid = shmget(SHM_CTRLID, sizeof(struct ctrlMem), 0600)) < 0)
  {
    printf("Unable to get shared memory segment\n");
    return(-1);
  }

  // Now we attach the segment to our data space.
  if((shmCtrl = shmat(shmctrlid, NULL, 0)) == (struct ctrlMem *) -1)
  {
    printf("Unable to attach segment\n");
    return(-1);
  }
  return 0;
}
