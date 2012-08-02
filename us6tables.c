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
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "incs/common.h"
#include "incs/us6tables.h"
#include "incs/filter.h"
#include "incs/commands.h"

/**
 * Print an help for this program
 */
void printHelp()
{
  printf("Usage: us6tables -[AD] chain rule-specification [options]\n");
  printf("       us6tables -[RI] chain rulenum rule-specification [options]\n");
  printf("       us6tables -D chain rulenum\n");
  printf("       us6tables -[LFZ] [chain] [options]\n");
  printf("       us6tables -[NX] chain\n");
  printf("       us6tables -E old-chain-name new-chain-name\n");
  printf("       us6tables -P chain target\n");
  printf("       us6tables -h (print this help information)\n");
  printf("       us6tables -V (print package version)\n\n");

  printf("Commands:\n");
  printf("Either long or short options are allowed.\n");
  printf("  --version -V                  print package version.\n");
  printf("  --help    -h                  print this help\n");
  printf("  --append  -A chain            Append to chain\n");
  printf("  --delete  -D chain            Delete matching rule from chain\n");
  printf("  --delete  -D chain rulenum\n");
  printf("                                Delete rule rulenum (1 = first) from chain\n");
  printf("  --insert  -I chain [rulenum]\n");
  printf("                                Insert in chain as rulenum (default 1=first)\n");
  printf("  --replace -R chain rulenum\n");
  printf("                                Replace rule rulenum (1 = first) in chain\n");
  printf("  --list    -L [chain]          List the rules in a chain or all chains\n");
  printf("  --flush   -F [chain]          Delete all rules in  chain or all chains\n");
  printf("  --zero    -Z [chain]          Zero counters in chain or all chains\n");
  printf("  --new     -N chain            Create a new user-defined chain\n");
  printf("  --delete-chain\n");
  printf("            -X [chain]          Delete a user-defined chain\n");
  printf("  --policy  -P chain target\n");
  printf("                                Change policy on chain to target\n");
  printf("  --rename-chain\n");
  printf("            -E old-chain new-chain\n");
  printf("                                Change chain name, (moving any references)\n");
  printf("Options:\n");
  printf("  --proto       -p [!] proto    protocol: by number or name, eg. `tcp'\n");
  printf("  --source      -s [!] address[/mask]\n");
  printf("                                source specification\n");
  printf("  --destination -d [!] address[/mask]\n");
  printf("                                destination specification\n");
  printf("  --numeric     -n              numeric output of addresses and ports\n");
  printf("  --verbose     -v              verbose mode\n");
  printf("  --line-numbers                print line numbers when listing\n");
  printf("  --exact       -x              expand numbers (display exact values)\n");
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
  nOptions = 0;
  bzero(chain, 50);

  while(!stop)
  {
    int option_index = 0, c;
    static struct option long_options[] = {
                                              {"help", no_argument , 0, 'h'},
                                              {"version", no_argument , 0, 'V' },
                                              {"append", required_argument, 0, 'A' },
                                              {"delete", required_argument, 0, 'D' },
                                              {"insert", required_argument, 0, 'I' },
                                              {"replace", required_argument, 0, 'R' },
                                              {"list", optional_argument, 0, 'L' },
                                              {"flush", optional_argument, 0, 'F' },
                                              {"zero", optional_argument, 0, 'Z' },
                                              {"policy", required_argument, 0, 'P' },
                                              {"new", required_argument, 0, 'N' },
                                              {"delete-chain", optional_argument, 0, 'X' },
                                              {"rename-chain", required_argument, 0, 'E' },
                                              {"numeric", no_argument , 0, 'n' },
                                              {"verbose", no_argument , 0, 'v' },
                                              {"line-numbers", no_argument , 0, 'q' },
                                              {"exact", no_argument , 0, 'x' },
                                              {0, 0, 0, 0}
                                          };
    c = getopt_long(argc, argv, "hVA:D:I:R:L::F::Z::P:N:X::E:nvqx", long_options, &option_index);
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
      case 'A':
        command = APPEND;
        paramIndex = optind;
        strcpy(chain, optarg);
        stop = 1;
      break;
      case 'D':
        command = DELETE;
        paramIndex = optind;
        strcpy(chain, optarg);
        stop = 1;
      break;
      case 'I':
        command = INSERT;
        paramIndex = optind;
        strcpy(chain, optarg);
        stop = 1;
      break;
      case 'R':
        command = REPLACE;
        paramIndex = optind;
        strcpy(chain, optarg);
        stop = 1;
      break;
      case 'L':
        command = LIST;
        paramIndex = optind;
        if(argv[paramIndex] != NULL)
        {
          while(argv[paramIndex] != NULL && argv[paramIndex][0] == '-' && paramIndex < argc)
            paramIndex++;
          if(argv[paramIndex] != NULL)
            strcpy(chain, argv[paramIndex]);
        }
      break;
      case 'F':
        command = FLUSH;
        paramIndex = optind;
        if(argv[optind] != NULL)
          strcpy(chain, argv[optind]);
      break;
      case 'Z':
        command = ZERO;
        paramIndex = optind;
        if(argv[optind] != NULL)
          strcpy(chain, argv[optind]);
      break;
      case 'P':
        command = POLICY;
        paramIndex = optind;
        strcpy(chain, optarg);
      break;
      case 'N':
        command = NEWCHAIN;
        paramIndex = optind;
        strcpy(chain, optarg);
      break;
      case 'X':
        command = DELETECHAIN;
        paramIndex = optind;
        if(argv[optind] != NULL)
          strcpy(chain, argv[optind]);
      break;
      case 'E':
        command = RENAMECHAIN;
        paramIndex = optind;
        strcpy(chain, optarg);
      break;
      case 'p':
        option[nOptions++] = PROTO;
      break;
      case 's':
        option[nOptions++] = SOURCE;
      break;
      case 'd':
        option[nOptions++] = DESTINATION;
      break;
      case 'n':
        option[nOptions++] = NUMERIC;
      break;
      case 'v':
        option[nOptions++] = VERBOSE;
      break;
      case 'q':
        option[nOptions++] = LINENO;
      break;
      case 'x':
        option[nOptions++] = EXACT;
      break;
      default:
      break;
    }
  }
}

int main(int argc, char **argv)
{
  int error = 0;
  
  handleOptions(argc, argv);

  if(command != NOCMD)
  {
    if(bindToRulesSpace(SHM_ID) != 0)
    {
      if(createRulesSpace(SHM_ID) != 0)
      {
        exit(-1);
      }
    }
    
    prgArgv = argv;
    prgArgc = argc;
    switch(command)
    {
      case APPEND:
        error = cmdAppend();
      break;
      case DELETE:
        error = cmdDelete();
      break;
      case INSERT:
        error = cmdInsert();
      break;
      case REPLACE:
        error = cmdReplace();
      break;
      case LIST:
        error = cmdList();
      break;
      case FLUSH:
        error = cmdFlush();
      break;
      case ZERO:
        error = cmdZero();
      break;
      case POLICY:
        error = cmdPolicy();
      break;
      case NEWCHAIN:
        error = cmdNewChain();
      break;
      case DELETECHAIN:
        error = cmdDeleteChain();
      break;
      case RENAMECHAIN:
        error = cmdRenameChain();
      break;
      default:
      break;
    }

// Freeing memory for the firewall rules
    if(freeRulesSpace() != 0)
      printf("Unable to detach shared memory\n");
  }
  else
  {
    printf("us6tables v%s: no command specified\n", CURRENTVERSION);
    printf("Try `us6tables -h' or 'us6tables --help' for more information.\n");
    exit(2);
  }

  return error;
}
