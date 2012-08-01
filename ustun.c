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
#include <assert.h>
#include <signal.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <memory.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <netinet/in.h>
#include "incs/clist.h"
#include "incs/common.h"
#include "incs/logger.h"
#include "incs/filter.h"
#include "incs/state.h"
#include "incs/ustun.h"
#include "incs/inout.h"
#include "incs/ctrl.h"

/**
 * Print an help for this program
 */
void printHelp()
{
  printf("  -h --help           This text\n");
  printf("  -V --version        Version number of this program\n");
  printf("  -v --verbose        Be verbose (can be given more than once)\n");
  printf("  -s --log-stderr     Log to stderr, instead of syslog\n");
  printf("  -p --pidfile <FILE> Save the PID in <FILE> (default: %s). Only used if NOT started with -s\n", DEFAULT_PIDFILE);
  printf("  -n --devname <name> The name of the created device (default tunX)\n");
  printf("  -r --remoteip <IP>  The IP of the remote Tunnelserver\n");
  printf("  -l --localeip <IP>  The local IP\n");
  printf("  -m --mode <MODE>    Tunnelmode. 6to4, tunnelbroker, isatap\n");
}

/**
 * Print the version of this program
 */
void printVersion()
{
  printf("Userspace Tunnel with buildin Firewall ver. %s\nThis programm will be distributed unter GPL2.0\n\n", CURRENTVERSION);
}

/**
 * Check if the given IP is valid
 *
 * @param char *ipAddr       the given IP to check
 * @return int               0 if valid, -1 if invalid, -2 if not IP
 */
int isValidIP(char *ipAddr)
{
  char *p, *ipS;
  int ip[4], l = 0, nan = 0;
  size_t k;

  ipS = strdup(ipAddr);
  p = strtok(ipS, ".");
  while(p != NULL)
  {
    for(nan = k = 0; k < strlen(p); k++)
      if(p[k] < '0' || p[k] > '9')
        nan = 1;
    if(nan == 0)
    {
      ip[l++] = atoi(p);
      p = strtok(NULL, ".");
    }
    else
      break;
  }
  free(ipS);
  if(nan == 0)
  {
    if(!((ip[0] != 0) && (ip[0] <= 255) && (ip[1] <= 255) && (ip[2] <= 255) && (ip[3] <= 255)))
      return -1;
    else
      return 0;
  }
  else
    return -2;
}

/**
 * Manage the command line parameters
 *
 * @param int argc           the number of the parameters in the command line
 * @param char **argv        the command line parameters
 */
void handleOptions(int argc, char **argv)
{
  verboseLevel = 0;

  bzero(pidFile, 255);
  strcpy(pidFile, DEFAULT_PIDFILE);
  logTo = SYSLOG;
  while(1)
  {
    int option_index = 0, c;
    static struct option long_options[] = {
                                              {"help", no_argument, 0, 'h'},
                                              {"version", no_argument, 0, 'V' },
                                              {"verbose", no_argument, 0, 'v' },
                                              {"log-stderr", no_argument, 0, 's' },
                                              {"pidfile", required_argument, 0, 'p' },
                                              {"devname", required_argument, 0, 'n' },
                                              {"remoteip", required_argument, 0, 'r' },
                                              {"localip", required_argument, 0, 'l' },
                                              {"mode", required_argument, 0, 'm' },
                                              {0, 0, 0, 0}
                                          };
    c = getopt_long(argc, argv, "hVvsp:n:r:l:m:", long_options, &option_index);
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
      case 'v':
        verboseLevel++;
      break;
      case 's':
        logTo = STDERR;
      break;
      case 'p':
        strcpy(pidFile, optarg);
      break;
      case 'n':
        strcpy(devname, optarg);
      break;
      case 'r':
        switch(isValidIP(optarg))
        {
          case 0:
            strcpy(remoteIP, optarg);
          break;
          case -1:
            printf("Invalid IP address! Parameter will be ignored!\n");
          break;
          case -2:
            printf("You MUST give an IP address! Parameter will be ignored!\n");
          break;
        }
      break;
      case 'l':
        switch(isValidIP(optarg))
        {
          case 0:
            strcpy(localIP, optarg);
          break;
          case -1:
            printf("Invalid IP address! Parameter will be ignored!\n");
          break;
          case -2:
            printf("You MUST give an IP address! Parameter will be ignored!\n");
          break;
        }
      break;
      case 'm':
        if(strcmp(optarg, "6to4") == 0)
          mode = MODE_6TO4;
        else if(strcmp(optarg, "tunnelbroker") == 0)
          mode = MODE_TUNNELBROKER;
        else if(strcmp(optarg, "isatap") == 0)
          mode = MODE_ISATAP;
        else
          printf("Invalid mode!\n");
      break;
      default:
      break;
    }
  }
}

/**
 * Create the tunnel device
 */
int createTUN()
{
  struct ifreq ifr;
  int fd, err;
  int dontblock = 1;

  assert(devname != NULL);
  if((fd = open("/dev/net/tun", O_RDWR)) < 0)
    return fd;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags |= IFF_TUN;
  if(*devname != '\0')
      strncpy(ifr.ifr_name, devname, IFNAMSIZ);
  if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
  {
    close(fd);
    return err;
  }
  strcpy(devname, ifr.ifr_name);

  if(ioctl(fd, FIONBIO, (char *) &dontblock) == -1)
  {
    printf("Unable to set socket as non blocking\n");
    exit(-1);
  }

  return fd;
}

/**
 * Catchfunction for the configured signals
 *
 * @param int signal         the signal
 */
static void signalHandler(int signal)
{
  switch (signal)
  {
    case SIGINT:
    case SIGTERM:
      stopUSTun();
    break;
    default:
    break;
  }
}

/**
 * Start the program as daemon
 */
void daemonize(void)
{
  pid_t pid, sid;
  FILE *fp;

  pid = fork();
  if(pid < 0)
    exit(EXIT_FAILURE);
  if(pid > 0)
  {
    fp = fopen(pidFile, "wt");
    fprintf(fp, "%d\n", pid);
    fclose(fp);
    logger(LOG_INFO, "USTun", "Successfully daemonized. PID: %d", pid);
    exit(EXIT_SUCCESS);
  }

  umask(0);

  sid = setsid();
  if(sid < 0)
    exit(EXIT_FAILURE);
  if((chdir("/")) < 0)
    exit(EXIT_FAILURE);

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

int main(int argc, char **argv)
{
  int ifBind;
  struct sockaddr_in localaddr;
  struct threadArgs args6to4, args4to6;
  pthread_t id6to4, id4to6, idCtrl;
  int dontblock = 1;
  char *ipStr;
  pid_t pid = 0;
  FILE *fp;

  mode = -1;
  strcpy(devname, "");
  strcpy(localIP, "");
  strcpy(remoteIP, "");

  handleOptions(argc, argv);

  if(strlen(localIP) == 0 || strlen(remoteIP) == 0 || mode < 0)
  {
    printf("You MUST provide valid remote and local IP and tunnel mode\n");
    exit(-1);
  }

// Creates the device
  if((tun = createTUN()) < 0)
  {
    printf("Unable to create tunnel device\n");
    exit(-1);
  }
  logger(LOG_INFO, "USTun", "TUN name is %s", devname);

// Now open the socket for the tunnel
  if((sockv6 = socket(AF_INET, SOCK_RAW, IPPROTO_IPV6)) < 0)
  {
    printf("Unable to create socket\n");
    exit(-1);
  }
  logger(LOG_INFO, "USTun", "IPv4 SOCK_RAW created: %d", sockv6);

  strcpy(localIPStr, localIP);
  strcpy(remoteIPStr, remoteIP);

  localaddr.sin_family = AF_INET;
  localaddr.sin_port = htons(IPPROTO_IPV6);
  localaddr.sin_addr.s_addr = inet_addr(localIP);
  bzero(&(localaddr.sin_zero), 8);
  if(localaddr.sin_addr.s_addr != -1)
  {
    if((ifBind = bind(sockv6, (struct sockaddr *)&localaddr, sizeof(struct sockaddr))) < 0)
    {
      printf("Unable to bind to local address\n");
      exit(-1);
    }
    ipStr = printIPv4(localaddr.sin_addr.s_addr);
    logger(LOG_INFO, "USTun", "Bind local IPv4 address: %s", ipStr);
    free(ipStr);
  }

  if(ioctl(sockv6, FIONBIO, (char *) &dontblock) == -1)
  {
    printf("Unable to set socket as non blocking\n");
    exit(-1);
  }

// Setup remote endpoint
  args4to6.sockv6 = args6to4.sockv6 = sockv6;
  args4to6.tun = args6to4.tun = tun;
  args4to6.tunMode = args6to4.tunMode = mode;
  args4to6.localIP = args6to4.localIP = localaddr.sin_addr.s_addr;
  switch(mode)
  {
    case MODE_6TO4:
      args4to6.remoteIP = args6to4.remoteIP = inet_addr("192.88.99.1");
    break;
    case MODE_TUNNELBROKER:
      args4to6.remoteIP = args6to4.remoteIP = inet_addr(remoteIP);
    break;
    case MODE_ISATAP:
      args4to6.remoteIP = args6to4.remoteIP = inet_addr(remoteIP);
    break;
    default:
      printf("Invalid mode. Exiting...\n");
      exit(-1);
    break;
  }
  ipStr = printIPv4(args6to4.remoteIP);
  logger(LOG_INFO, "USTun", "Using remote IPv4: %s", ipStr);
  free(ipStr);

// Allocate memory for the firewall rules
  if(bindToRulesSpace(SHM_ID) != 0)
  {
    if(createRulesSpace(SHM_ID) != 0)
    {
      exit(-1);
    }
  }
  
// Allocate memory for the established list
  if((conntracks = createCList()) == NULL)
  {
    printf("Unable to allocate memory for conntracks...\n");
    exit(-1);
  }

// Init semaphore for managing conntracks
  sem_init(&mutex, 0, 1);

  if(pipe(pipe6to4) != 0)
  {
    printf("Unable to init pipe...\n");
    exit(-1);
  }
  if(pipe(pipe4to6) != 0)
  {
    printf("Unable to init pipe...\n");
    exit(-1);
  }

  args4to6.fd = pipe4to6[0];
  args6to4.fd = pipe6to4[0];
  hasToStop = 0;
  signal(SIGINT, &signalHandler);
  signal(SIGTERM, &signalHandler);

  if(logTo != STDERR)
    daemonize();

  if ((fp = fopen(pidFile, "r"))) {
    fscanf(fp, "%d\n", &pid);
    fclose(fp);
  }
  args4to6.pid = pid;
  args4to6.pid = pid;

// Start the Threads for incoming and outgoing packets
  if(pthread_create(&id6to4, NULL, (void *)io6to4, (void *)&args6to4) != 0)
  {
    printf("Unable to create pThread...\n");
    exit(-1);
  }
  if(pthread_create(&id4to6, NULL, (void *)io4to6, (void *)&args4to6) != 0)
  {
    printf("Unable to create pThread...\n");
    exit(-1);
  }
  if(pthread_create(&idCtrl, NULL, (void *)ctrl, (void *)&args4to6) != 0)
  {
    printf("Unable to create pThread...\n");
    exit(-1);
  }
  if(pthread_join(id6to4, NULL) != 0)
  {
    printf("Unable to start pThread...\n");
    exit(-1);
  }
  if(pthread_join(id4to6, NULL) != 0)
  {
    printf("Unable to start pThread...\n");
    exit(-1);
  }
  if(pthread_join(idCtrl, NULL) != 0)
  {
    printf("Unable to start pThread...\n");
    exit(-1);
  }

  return 0;
}
