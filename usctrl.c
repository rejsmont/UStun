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
#include <getopt.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <arpa/inet.h>
#include "incs/common.h"
#include "incs/usctrl.h"
#include "incs/ctrl.h"
#include "incs/filter.h"

/**
 * Print an help for this program
 */
void printHelp()
{
  printf("  -h --help                  This text\n");
  printf("  -V --version               Version number of this program\n");
  printf("  -i --get-info              Print information about the tunnel\n");
  printf("  -v --set-verbose <level>   Change the verbose level of the ustun-module\n");
  printf("  -q --quit                  Quit the ustun-module\n");
  printf("  -c --get-conntracks        Print the connection tracking table\n");
  printf("  -f --flush-conntracks      Flush the connection tracking table\n");
  printf("  -d --delete-conntrack <n>  Delete the given connection from the connection tracking table\n");
  printf("  -p --pid <pid>             Specify PID of tunnel to control\n");
  printf("  -D --destroy               Destroy firewall and free its memory\n");
}

/**
 * Print the version of this program
 */
void printVersion()
{
  printf("Userspace Tunnel with buildin Firewall ver. %s\nThis programm will be distributed unter GPL2.0\n\n", CURRENTVERSION);
}

/**
 * Manage the command line parameters
 *
 * @param int argc           the number of the parameters in the command line
 * @param char **argv        the command line parameters
 */
void handleOptions(int argc, char **argv)
{
  uint8_t stop = 0;

  command = NOCMD;

  while(!stop)
  {
    int option_index = 0, c;
    static struct option long_options[] = {
                                              {"help", no_argument , 0, 'h'},
                                              {"version", no_argument , 0, 'V' },
                                              {"get-info", no_argument , 0, 'i' },
                                              {"set-verbose", required_argument , 0, 'v' },
                                              {"quit", no_argument , 0, 'q' },
                                              {"get-conntracks", no_argument , 0, 'c' },
                                              {"flush-conntracks", no_argument , 0, 'f' },
                                              {"delete-conntrack", required_argument , 0, 'd' },
                                              {"pid", required_argument , 0, 'p' },
                                              {"destroy", no_argument , 0, 'D' },
                                              {0, 0, 0, 0}
                                          };
    c = getopt_long(argc, argv, "hViv:qcfd:p:D", long_options, &option_index);
    if(c == -1)
      break;

    switch(c)
    {
      case 'h':
        printVersion();
        printHelp();
        exit(0);
      break;
      case 'V':
        printVersion();
        exit(0);
      break;
      case 'i':
        command = GETINFO;
      break;
      case 'v':
        command = SETVERBOSE;
        param = atoi(optarg);
      break;
      case 'q':
        command = QUIT;
      break;
      case 'c':
        command = GETCONNTRACKS;
      break;
      case 'f':
        command = FLUSHCONNTRACKS;
      break;
      case 'd':
        command = DELETECONNTRACK;
        param = atoi(optarg);
      break;
      case 'p':
        pid = atoi(optarg);
      break;
      case 'D':
        command = DESTROY;
      break;

      default:
      break;
    }
  }
}

/**
 * Send a command to the ustun-module
 *
 * @param char *param        the parameter (or NULL if there are no parameters)
 */
void sendCommand(char *param)
{
  bool stop;

  shmCtrl->cmd = command;
  if(param != NULL)
    strcpy(shmCtrl->param, param);
  shmCtrl->executeCmd = 1;

// Cycle the answer
  stop = FALSE;
  while(stop == FALSE)
  {
    if(shmCtrl->validAnswer == 1)
    {
      printf("%s\n", shmCtrl->answer);
      if(shmCtrl->lastAnswer == 1)
        stop = TRUE;
      shmCtrl->gotAnswer = 1;
      usleep(250);
    }
    usleep(250);
  }
}

int main(int argc, char **argv)
{
  char paramStr[255];
  int shmid;
  struct shmid_ds fwshm;

  handleOptions(argc, argv);


  if(command != NOCMD)
  {
    if(command == DESTROY) {
      if((shmid = shmget(SHM_ID, sizeof(struct firewall), 0600)) < 0)
      {
        printf("Unable to get shared memory segment\n");
        return(-1);
      }
      if ((shmctl(shmid, IPC_STAT, &fwshm) == 0)&&(fwshm.shm_nattch == 0)) {
        printf("Freeing %d bytes for firewall rules\n", sizeof(struct firewall));
        return shmctl(shmid, IPC_RMID, 0);
      } else {
        if (fwshm.shm_nattch > 0)
          printf("There are still %d tunnels attached\n", fwshm.shm_nattch);
        else
          printf("Unable to get info aboutshared memory segment\n");
        return(-1);
      }
    }

    if(pid <= 0) {
      printf("No tunnel PID specified\n");
      exit(5);
    }

    if(bindToCtrlSpace(pid) != 0)
      exit(-1);

    bzero(paramStr, 255);
    if((command == SETVERBOSE) || (command == DELETECONNTRACK))
    {
      sprintf(paramStr, "%d", param);
      sendCommand(paramStr);
    }
    else
      sendCommand(NULL);

// Freeing memory for the control interface
    if(freeCtrlSpace() != 0)
      printf("Unable to detach shared memory\n");
  }
  else
  {
    printf("usctrl v%s: no command specified\n", CURRENTVERSION);
    printf("Try `usctrl -h' or 'usctrl --help' for more information.\n");
    exit(2);
  }

  return 0;
}
