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
#include <errno.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include "incs/common.h"
#include "incs/filter.h"
#include "incs/state.h"
#include "incs/commands.h"
#include "incs/us6tables.h"

/**
 * Check if the given string is a number
 *
 * @return int                    1 if the given string is numeric
 */
int isNumeric(char *s)
{
  char *p;

  if(strtol(s, &p, 10) == EINVAL)
    return 0;
  if(p == s)
    return 0;
  return 1;
}

/**
 * Get the rule description from user's given parameters
 *
 * @return struct fwRule*         the rule description or NULL on errors
 */
struct fwRule *getRuleDescription(void)
{
  struct fwRule *rule;
  struct protoent *proto;
  struct servent *serv;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_in6 *ipv6;
  char addr[255], *t;
  int l, k, f, endMatch;

  rule = malloc(sizeof(struct fwRule));
  memset(rule, 0, sizeof(struct fwRule));
  rule->extraChainNumber = -1;
  for(l = paramIndex; l < prgArgc; l++)
  {
    if(strcmp(prgArgv[l], "-p") == 0 || strcmp(prgArgv[l], "--protocol") == 0)
    {
      if(prgArgv[l + 1][0] == '!')
      {
        rule->notProto = 1;
        l++;
      }
      proto = getprotobyname(prgArgv[l + 1]);
      if(proto != NULL)
        rule->proto = proto->p_proto;
      else
      {
        printf("us6tables: unknown protocol `%s' specified\n", prgArgv[l + 1]);
        return NULL;
      }
      l++;
    }
    else if(strcmp(prgArgv[l], "--icmpv6-type") == 0 && (rule->proto == 58))
    {
      if(prgArgv[l + 1][0] == '!')
      {
        rule->notType = 1;
        l++;
      }
      rule->type = atoi(prgArgv[l + 1]);
      l++;
    }
    else if(strcmp(prgArgv[l], "-s") == 0 || strcmp(prgArgv[l], "--source") == 0)
    {
      if(prgArgv[l + 1][0] == '!')
      {
        rule->notSrcAddr = 1;
        l++;
      }
      bzero(addr, 255);
      strcpy(addr, prgArgv[l + 1]);
      if(strchr(addr, '/') == NULL)
        inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &rule->srcAddr.mask);
      else
      {
        rule->srcAddr.mask = getIPv6Network(atoi(strchr(addr, '/') + 1));
        *(strchr(addr, '/')) = 0;
      }
      if(inet_pton(AF_INET6, addr, &rule->srcAddr.ip) == 0)
      {
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        if(getaddrinfo(addr, NULL, &hints, &servinfo) != 0)
        {
          printf("us6tables: error by parsing `%s' (not IPv6 address?)\n", addr);
          return NULL;
        }
        else
        {
          for(p = servinfo;p != NULL; p = p->ai_next)
          {
            ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            rule->srcAddr.ip = ipv6->sin6_addr;
            break;
          }
        }
        freeaddrinfo(servinfo);
      }
      l++;
    }
    else if(strcmp(prgArgv[l], "--log-prefix") == 0 && (rule->action == LOG))
    {
      bzero(rule->log.prefix, 30);
      strcpy(rule->log.prefix, prgArgv[l + 1]);
      l++;
    }
    else if(strcmp(prgArgv[l], "--log-level") == 0 && (rule->action == LOG))
    {
      rule->log.level = atoi(prgArgv[l + 1]);
      l++;
    }
    else if(strcmp(prgArgv[l], "--sport") == 0 || strcmp(prgArgv[l], "--source-port") == 0)
    {
      if(prgArgv[l + 1][0] == '!')
      {
        rule->notSrcPort = 1;
        l++;
      }
      if(isNumeric(prgArgv[l + 1]) == 1)
        rule->srcPort = atoi(prgArgv[l + 1]);
      else
      {
        serv = getservbyname(prgArgv[l + 1], NULL);
        if(serv != NULL)
          rule->srcPort = ntohs(serv->s_port);
        else
        {
          printf("us6tables: invalid port/service `%s' specified\n", prgArgv[l + 1]);
          return NULL;
        }
      }
      l++;
    }
    else if(strcmp(prgArgv[l], "-d") == 0 || strcmp(prgArgv[l], "--destination") == 0)
    {
      if(prgArgv[l + 1][0] == '!')
      {
        rule->notSrcAddr = 1;
        l++;
      }
      bzero(addr, 255);
      strcpy(addr, prgArgv[l + 1]);
      if(strchr(addr, '/') == NULL)
        inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &rule->dstAddr.mask);
      else
      {
        rule->dstAddr.mask = getIPv6Network(atoi(strchr(addr, '/') + 1));
        *(strchr(addr, '/')) = 0;
      }
      if(inet_pton(AF_INET6, addr, &rule->dstAddr.ip) == 0)
      {
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        if(getaddrinfo(addr, NULL, &hints, &servinfo) != 0)
        {
          printf("us6tables: error by parsing `%s' (not IPv6 address?)\n", addr);
          return NULL;
        }
        else
        {
          for(p = servinfo;p != NULL; p = p->ai_next)
          {
            ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            rule->dstAddr.ip = ipv6->sin6_addr;
            break;
          }
        }
        freeaddrinfo(servinfo);
      }
      l++;
    }
    else if(strcmp(prgArgv[l], "--dport") == 0 || strcmp(prgArgv[l], "--destination-port") == 0)
    {
      if(prgArgv[l + 1][0] == '!')
      {
        rule->notDstPort = 1;
        l++;
      }
      if(isNumeric(prgArgv[l + 1]) == 1)
        rule->dstPort = atoi(prgArgv[l + 1]);
      else
      {
        serv = getservbyname(prgArgv[l + 1], NULL);
        if(serv != NULL)
          rule->dstPort = ntohs(serv->s_port);
        else
        {
          printf("us6tables: invalid port/service `%s' specified\n", prgArgv[l + 1]);
          return NULL;
        }
      }
      l++;
    }
    else if(strcmp(prgArgv[l], "-j") == 0 || strcmp(prgArgv[l], "--jump") == 0)
    {
      if(strcmp(prgArgv[l + 1], "ACCEPT") == 0)
        rule->action = ACCEPT;
      else if(strcmp(prgArgv[l + 1], "REJECT") == 0)
        rule->action = REJECT;
      else if(strcmp(prgArgv[l + 1], "DROP") == 0)
        rule->action = DROP;
      else if(strcmp(prgArgv[l + 1], "LOG") == 0)
        rule->action = LOG;
      else
      {
        for(f = k = 0; k < shmFW->nChains; k++)
          if(strcmp(shmFW->chains[k].name, prgArgv[l + 1]) == 0)
          {
            f = 1;
            rule->extraChainNumber = k;
          }
        if(f == 0)
        {
          printf("us6tables: unknown target `%s'\n", prgArgv[l + 1]);
          return NULL;
        }
      }
      l++;
    }
    else if(strcmp(prgArgv[l], "-m") == 0 || strcmp(prgArgv[l], "--match") == 0)
    {
      if(strcmp(prgArgv[l + 1], "comment") == 0)
      {
        for(f = 0, k = l + 2; (k < prgArgc) && (f == 0); k++, l++)
        {
          if(strcmp(prgArgv[k], "--comment") == 0)
          {
            if((k + 1) >= prgArgc)
            {
              printf("us6tables: Unknown arg `--comment'\n");
              return NULL;
            }
            strcpy(rule->comment, prgArgv[k + 1]);
            f = 1;
            endMatch = k;
            break;
          }
        }
        if(f == 0)
        {
          printf("us6tables: COMMENT match: You must specify `--comment'\n");
          return NULL;
        }
      }
      else if(strcmp(prgArgv[l + 1], "state") == 0)
      {
        for(f = 0, k = l + 2; (k < prgArgc) && (f == 0); k++, l++)
        {
          if(strcmp(prgArgv[k], "--state") == 0)
          {
            if((k + 1) >= prgArgc)
            {
              printf("us6tables: Unknown arg `--state'\n");
              return NULL;
            }
            t = strtok(prgArgv[k + 1], ",");
            while(t != NULL)
            {
              if(t != NULL)
              {
                if(strcmp(t, "NEW") == 0)
                  rule->states |= STATE_NEW;
                if(strcmp(t, "RELATED") == 0)
                  rule->states |= STATE_RELATED;
                if(strcmp(t, "ESTABLISHED") == 0)
                  rule->states |= STATE_ESTABLISHED;
                t = strtok(NULL, ",");
              }
            }
            f = 1;
            endMatch = k;
            break;
          }
        }
        if(f == 0)
        {
          printf("us6tables: You must specify `--state'\n");
          return NULL;
        }
      }
      else if(strcmp(prgArgv[l + 1], "multiport") == 0)
      {
        for(f = 0, k = l + 2; (k < prgArgc) && (f == 0); k++, l++)
        {
          if((strcmp(prgArgv[k], "--source-ports") == 0) || (strcmp(prgArgv[k], "--sports") == 0))
          {
            if((k + 1) >= prgArgc)
            {
              printf("us6tables: Unknown arg `--source-ports'\n");
              return NULL;
            }
            if(prgArgv[k + 1][0] == '!')
            {
              rule->notMultiport = 1;
              k++;
            }
            t = strtok(prgArgv[k + 1], ",");
            while(t != NULL)
            {
              if(t != NULL)
              {
                if(isNumeric(t) == 1)
                  rule->srcMultiPorts.ports[rule->srcMultiPorts.nPorts++] = atoi(t);
                else
                {
                  serv = getservbyname(t, NULL);
                  if(serv != NULL)
                    rule->srcMultiPorts.ports[rule->srcMultiPorts.nPorts++] = ntohs(serv->s_port);
                  else
                  {
                    printf("us6tables: invalid port/service `%s' specified\n", t);
                    return NULL;
                  }
                }
                t = strtok(NULL, ",");
              }
            }
            f = 1;
            endMatch = k;
            break;
          }
          else if((strcmp(prgArgv[k], "--destination-ports") == 0) || (strcmp(prgArgv[k], "--dports") == 0))
          {
            if((k + 1) >= prgArgc)
            {
              printf("us6tables: Unknown arg `--destination-ports'\n");
              return NULL;
            }
            if(prgArgv[k + 1][0] == '!')
            {
              rule->notMultiport = 1;
              k++;
            }
            t = strtok(prgArgv[k + 1], ",");
            while(t != NULL)
            {
              if(t != NULL)
              {
                if(isNumeric(t) == 1)
                  rule->dstMultiPorts.ports[rule->dstMultiPorts.nPorts++] = atoi(t);
                else
                {
                  serv = getservbyname(t, NULL);
                  if(serv != NULL)
                    rule->dstMultiPorts.ports[rule->dstMultiPorts.nPorts++] = ntohs(serv->s_port);
                  else
                  {
                    printf("us6tables: invalid port/service `%s' specified\n", t);
                    return NULL;
                  }
                }
                t = strtok(NULL, ",");
              }
            }
            f = 1;
            endMatch = k;
            break;
          }
          else if(strcmp(prgArgv[k], "--ports") == 0)
          {
            if((k + 1) >= prgArgc)
            {
              printf("us6tables: Unknown arg `--ports'\n");
              return NULL;
            }
            if(prgArgv[k + 1][0] == '!')
            {
              rule->notMultiport = 1;
              k++;
            }
            t = strtok(prgArgv[k + 1], ",");
            while(t != NULL)
            {
              if(t != NULL)
              {
                if(isNumeric(t) == 1)
                  rule->srcMultiPorts.ports[rule->srcMultiPorts.nPorts++] = rule->dstMultiPorts.ports[rule->dstMultiPorts.nPorts++] = atoi(t);
                else
                {
                  serv = getservbyname(t, NULL);
                  if(serv != NULL)
                    rule->srcMultiPorts.ports[rule->srcMultiPorts.nPorts++] = rule->dstMultiPorts.ports[rule->dstMultiPorts.nPorts++] = ntohs(serv->s_port);
                  else
                  {
                    printf("us6tables: invalid port/service `%s' specified\n", t);
                    return NULL;
                  }
                }
                t = strtok(NULL, ",");
              }
            }
            f = 1;
            endMatch = k;
            break;
          }
        }
        if(f == 0)
        {
          printf("us6tables: You must specify `--ports | --destination-ports | --source-ports'\n");
          return NULL;
        }
      }
      else
      {
        printf("us6tables: unknown module `%s'\n", prgArgv[l + 1]);
        return NULL;
      }
      l = endMatch + 1;
    }
    else
    {
      printf("us6tables: unrecognized parameter `%s'\n", prgArgv[l]);
      return NULL;
    }
  }

  if((rule->action == NONE) && (rule->extraChainNumber == -1))
  {
    printf("us6tables: no action specified\n");
    return NULL;
  }
  return rule;
}

/**
 * Append a rule to the given chain
 */
void cmdAppend()
{
  int nR;
  struct chain *c = NULL;
  struct fwRule *rule;

  if(strcmp(chain, "") == 0)
  {
    printf("us6tables: -A requires a chain\n");
    return;
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0)
      c = &shmFW->chains[nR];
  if(c == NULL)
  {
    printf("us6tables: Bad built-in chain name\n");
    return;
  }
  if(c->nRules < MAX_RULES_NUM)
  {
    rule = getRuleDescription();
    if(rule != NULL)
    {
      memcpy(&c->rules[c->nRules], rule, sizeof(struct fwRule));
      c->nRules++;
      free(rule);
    }
  }
  else
  {
    printf("us6tables: No space left in memory\n");
    return;
  }
}

/**
 * Delete a rule from the given chain
 */
void cmdDelete()
{
  int nR, l;
  struct chain *c = NULL;

  if(strcmp(chain, "") == 0 || prgArgv[paramIndex] == NULL)
  {
    printf("us6tables: -D requires a chain and a line number\n");
    return;
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0)
      c = &shmFW->chains[nR];
  if(c == NULL)
  {
    printf("us6tables: Bad built-in chain name\n");
    return;
  }
  l = atoi(prgArgv[paramIndex]) - 1;   // Rules saved 0-based, but displayed 1-based
  for(nR = l; nR < c->nRules - 1; nR++)
    memcpy(&c->rules[nR], &c->rules[nR + 1], sizeof(struct fwRule));
  memset(&c->rules[c->nRules], 0, sizeof(struct fwRule));
  c->nRules--;
}

/**
 * Insert a rule to the given chain at the given position
 */
void cmdInsert()
{
  int nR, l;
  struct chain *c = NULL;
  struct fwRule *rule;

  if(strcmp(chain, "") == 0 || prgArgv[paramIndex] == NULL)
  {
    printf("us6tables: -I requires a chain and a line number\n");
    return;
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0)
      c = &shmFW->chains[nR];
  if(c == NULL)
  {
    printf("us6tables: Bad built-in chain name\n");
    return;
  }
  nR = atoi(prgArgv[paramIndex]) - 1;   // Rules saved 0-based, but displayed 1-based
  if(nR > c->nRules)
  {
    printf("us6tables: Bad rule number\n");
    return;
  }
  if((c->nRules + 1) >= MAX_RULES_NUM)
  {
    printf("us6tables: No space left in memory\n");
    return;
  }
  paramIndex++;
  rule = getRuleDescription();
  if(rule != NULL)
  {
    for(l = nR + 1; l < c->nRules; l++)
      memcpy(&c->rules[l], &c->rules[l - 1], sizeof(struct fwRule));
    memcpy(&c->rules[nR], rule, sizeof(struct fwRule));
    c->nRules++;
    free(rule);
  }
}

/**
 * Replace a rule from the given chain
 */
void cmdReplace()
{
  int nR;
  struct chain *c = NULL;
  struct fwRule *rule;

  if(strcmp(chain, "") == 0 || prgArgv[paramIndex] == NULL)
  {
    printf("us6tables: -R requires a chain and a line number\n");
    return;
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0)
      c = &shmFW->chains[nR];
  if(c == NULL)
  {
    printf("us6tables: Bad built-in chain name\n");
    return;
  }
  nR = atoi(prgArgv[paramIndex]) - 1;   // Rules saved 0-based, but displayed 1-based
  if(nR > c->nRules)
  {
    printf("us6tables: Bad rule number\n");
    return;
  }
  paramIndex++;
  rule = getRuleDescription();
  if(rule != NULL)
  {
    memcpy(&c->rules[nR], rule, sizeof(struct fwRule));
    free(rule);
  }
}

/**
 * List the rules (if given, just from given chain)
 */
void cmdList()
{
  char str[INET6_ADDRSTRLEN + 5], ip[255];
  int l, k, mp, nR, nRef, displayLineNo = 0, verbose = 0, numeric = 0, exact = 0;
  char *proto, *amP, *amB;
  struct servent *serv;
  struct hostent *host;

  if(strlen(chain) != 0)
  {
    for(l = -1, nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        l = nR;
    if(l == -1)
    {
      printf("us6tables: No chain/target/match by that name\n");
      return;
    }
  }
  for(l = 0; l < nOptions; l++)
  {
    if(option[l] == LINENO)
      displayLineNo = 1;
    if(option[l] == VERBOSE)
      verbose = 1;
    if(option[l] == NUMERIC)
      numeric = 1;
    if(option[l] == EXACT)
      exact = 1;
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0 || strlen(chain) == 0)
    {
      if(strcmp(shmFW->chains[nR].name, "INPUT") == 0 || strcmp(shmFW->chains[nR].name, "OUTPUT") == 0)
      {
        if(exact)
          printf("Chain %s (policy %s %lu packets, %llu bytes)\n",
            shmFW->chains[nR].name,
            (shmFW->chains[nR].policy == ACCEPT ? "ACCEPT" : (shmFW->chains[nR].policy == REJECT ? "REJECT" : "DROP")),
            shmFW->chains[nR].nPackets, shmFW->chains[nR].nBytes);
        else
        {
          amP = printAmount(shmFW->chains[nR].nPackets);
          amB = printAmount(shmFW->chains[nR].nBytes);
          printf("Chain %s (policy %s %s packets, %s bytes)\n",
            shmFW->chains[nR].name,
            (shmFW->chains[nR].policy == ACCEPT ? "ACCEPT" : (shmFW->chains[nR].policy == REJECT ? "REJECT" : "DROP")),
            amP, amB);
          free(amP);
          free(amB);
        }
      }
      else
      {
        for(nRef = l = 0; l < shmFW->nChains; l++)
          for(k = 0; k < shmFW->chains[l].nRules; k++)
            if(shmFW->chains[l].rules[k].extraChainNumber == nR)
              nRef++;
        printf("Chain %s (%d references)\n",
          shmFW->chains[nR].name,
          nRef);
      }
      if(displayLineNo)
        printf("num  ");
      if(verbose)
        printf(" pkts bytes");
      printf(" target    proto  source                         destination\n");

      for(l = 0; l < shmFW->chains[nR].nRules; l++)
      {
        if(displayLineNo == 1)
          printf("%-5d", l + 1);
        if(verbose)
        {
          if(exact)
            printf(" %4lu %5llu ", shmFW->chains[nR].rules[l].nPackets, shmFW->chains[nR].rules[l].nBytes); // Pakets, Bytes
          else
          {
            amP = printAmount(shmFW->chains[nR].rules[l].nPackets);
            amB = printAmount(shmFW->chains[nR].rules[l].nBytes);
            printf(" %4s %5s ", amP, amB); // Pakets, Bytes
            free(amP);
            free(amB);
          }
        }
        if(shmFW->chains[nR].rules[l].extraChainNumber != -1)
        {
          if(numeric)
            printf("%-9s all    ::/0                           ::/0\n", shmFW->chains[shmFW->chains[nR].rules[l].extraChainNumber].name);
          else
            printf("%-9s all    anywhere                       anywhere\n", shmFW->chains[shmFW->chains[nR].rules[l].extraChainNumber].name);
        }
        else
        {
          proto = getProto(shmFW->chains[nR].rules[l].proto);
          switch(shmFW->chains[nR].rules[l].action)
          {
            case ACCEPT:
              printf("ACCEPT   ");
            break;
            case REJECT:
              printf("REJECT   ");
            break;
            case DROP:
              printf("DROP     ");
            break;
            case LOG:
              printf("LOG      ");
            break;
            default:
            break;
          }
          if(shmFW->chains[nR].rules[l].notProto)
            printf("!");
          else
            printf(" ");
          printf("%-6s", proto);

          if(shmFW->chains[nR].rules[l].notSrcAddr)
            printf("!");
          else
            printf(" ");
          if(memcmp(&shmFW->chains[nR].rules[l].srcAddr.ip, &in6addr_any, sizeof(in6addr_any)))
          {
            if(numeric)
              inet_ntop(AF_INET6, &shmFW->chains[nR].rules[l].srcAddr.ip, ip, INET6_ADDRSTRLEN);
            else
            {
              host = gethostbyaddr(&shmFW->chains[nR].rules[l].srcAddr.ip, sizeof(struct in6_addr), AF_INET6);
              if(host != NULL)
                strcpy(ip, host->h_name);
              else
                inet_ntop(AF_INET6, &shmFW->chains[nR].rules[l].srcAddr.ip, ip, INET6_ADDRSTRLEN);
            }
            sprintf(str, "%s/%d", ip, getIPv6Mask(shmFW->chains[nR].rules[l].srcAddr.mask));
            printf("%-30s", str);
          }
          else
            printf("%-30s", (numeric == 1 ? "::/0" : "anywhere"));

          if(shmFW->chains[nR].rules[l].notDstAddr)
            printf("!");
          else
            printf(" ");
          if(memcmp(&shmFW->chains[nR].rules[l].dstAddr.ip, &in6addr_any, sizeof(in6addr_any)))
          {
            if(numeric)
              inet_ntop(AF_INET6, &shmFW->chains[nR].rules[l].dstAddr.ip, ip, INET6_ADDRSTRLEN);
            else
            {
              host = gethostbyaddr(&shmFW->chains[nR].rules[l].dstAddr.ip, sizeof(struct in6_addr), AF_INET6);
              if(host != NULL)
                strcpy(ip, host->h_name);
              else
                inet_ntop(AF_INET6, &shmFW->chains[nR].rules[l].dstAddr.ip, ip, INET6_ADDRSTRLEN);
            }
            sprintf(str, "%s/%d", ip, getIPv6Mask(shmFW->chains[nR].rules[l].dstAddr.mask));
            printf("%-30s ", str);
          }
          else
            printf("%-30s", (numeric == 1 ? "::/0" : "anywhere"));
          if((shmFW->chains[nR].rules[l].proto == PKGTYPE_ICMPv6) && (shmFW->chains[nR].rules[l].type != 0))
          {
            if(shmFW->chains[nR].rules[l].notType)
              printf("!");
            printf("ipv6-icmp type %d ", shmFW->chains[nR].rules[l].type);
          }
          if(shmFW->chains[nR].rules[l].states != STATE_NONE)
          {
            printf("state ");
            if((shmFW->chains[nR].rules[l].states & STATE_NEW) == STATE_NEW)
              printf("NEW");
            if((shmFW->chains[nR].rules[l].states & STATE_ESTABLISHED) == STATE_ESTABLISHED)
            {
              if((shmFW->chains[nR].rules[l].states & STATE_NEW) == STATE_NEW)
                printf(",");
              printf("ESTABLISHED");
            }
            if((shmFW->chains[nR].rules[l].states & STATE_RELATED) == STATE_RELATED)
            {
              if(((shmFW->chains[nR].rules[l].states & STATE_NEW) == STATE_NEW) ||
                 ((shmFW->chains[nR].rules[l].states & STATE_ESTABLISHED) == STATE_ESTABLISHED))
                printf(",");
              printf("RELATED");
            }
            printf(" ");
          }
          if(shmFW->chains[nR].rules[l].srcMultiPorts.nPorts != 0)
          {
            printf("multiport sports ");
            if(shmFW->chains[nR].rules[l].notMultiport)
              printf("!");
            for(mp = 0; mp < shmFW->chains[nR].rules[l].srcMultiPorts.nPorts; mp++)
            {
              if(mp != 0)
                printf(",");
              if(numeric)
                printf("%d", shmFW->chains[nR].rules[l].srcMultiPorts.ports[mp]);
              else
              {
                serv = getservbyport(htons(shmFW->chains[nR].rules[l].srcMultiPorts.ports[mp]), proto);
                if(serv != NULL)
                  printf("%s", serv->s_name);
                else
                  printf("%d", shmFW->chains[nR].rules[l].srcMultiPorts.ports[mp]);
              }
            }
            printf(" ");
          }
          if(shmFW->chains[nR].rules[l].dstMultiPorts.nPorts != 0)
          {
            printf("multiport dports ");
            if(shmFW->chains[nR].rules[l].notMultiport)
              printf("!");
            for(mp = 0; mp < shmFW->chains[nR].rules[l].dstMultiPorts.nPorts; mp++)
            {
              if(mp != 0)
                printf(",");
              if(numeric)
                printf("%d", shmFW->chains[nR].rules[l].dstMultiPorts.ports[mp]);
              else
              {
                serv = getservbyport(htons(shmFW->chains[nR].rules[l].dstMultiPorts.ports[mp]), proto);
                if(serv != NULL)
                  printf("%s", serv->s_name);
                else
                  printf("%d", shmFW->chains[nR].rules[l].dstMultiPorts.ports[mp]);
              }
            }
            printf(" ");
          }
          if(shmFW->chains[nR].rules[l].dstPort != 0)
          {
            if(shmFW->chains[nR].rules[l].notDstPort)
              printf("%s dpt:!", proto);
            else
              printf("%s dpt:", proto);
            if(numeric)
              printf("%d ", shmFW->chains[nR].rules[l].dstPort);
            else
            {
              serv = getservbyport(htons(shmFW->chains[nR].rules[l].dstPort), proto);
              if(serv != NULL)
                printf("%s", serv->s_name);
              else
                printf("%d", shmFW->chains[nR].rules[l].dstPort);
            }
          }
          if(shmFW->chains[nR].rules[l].srcPort != 0)
          {
            if(shmFW->chains[nR].rules[l].notSrcPort)
              printf("%s spt:!", proto);
            else
              printf("%s spt:", proto);
            if(numeric)
              printf("%d ", shmFW->chains[nR].rules[l].srcPort);
            else
            {
              serv = getservbyport(htons(shmFW->chains[nR].rules[l].srcPort), proto);
              if(serv != NULL)
                printf("%s", serv->s_name);
              else
                printf("%d", shmFW->chains[nR].rules[l].srcPort);
            }
          }
          free(proto);

          if(shmFW->chains[nR].rules[l].action == LOG)
          {
            printf("LOG flags 0 level %d ", (shmFW->chains[nR].rules[l].log.level != 0 ? shmFW->chains[nR].rules[l].log.level : 4));
            if(strlen(shmFW->chains[nR].rules[l].log.prefix) != 0)
              printf("prefix `%s' ", shmFW->chains[nR].rules[l].log.prefix);
          }

          if(strlen(shmFW->chains[nR].rules[l].comment) != 0)
            printf("/* %s */", shmFW->chains[nR].rules[l].comment);

          printf("\n");
        }
      }
      printf("\n");
    }
}

/**
 * Flush all rules (if given, just from given chain)
 */
void cmdFlush()
{
  int l, nR;

  if(strlen(chain) != 0)
  {
    for(l = -1, nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        l = nR;
    if(l == -1)
    {
      printf("us6tables: No chain/target/match by that name\n");
      return;
    }
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0 || strlen(chain) == 0)
    {
      shmFW->chains[nR].nRules = 0;
      memset(shmFW->chains[nR].rules, 0, sizeof(struct fwRule) * MAX_RULES_NUM);
    }
}

/**
 * Zeros the paket count (if given, just from given chain)
 */
void cmdZero()
{
  int l, nR;

  if(strlen(chain) != 0)
  {
    for(l = -1, nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        l = nR;
    if(l == -1)
    {
      printf("us6tables: No chain/target/match by that name\n");
      return;
    }
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0 || strlen(chain) == 0)
    {
      shmFW->chains[nR].nPackets = 0;
      shmFW->chains[nR].nBytes = 0;
    }
}

/**
 * Set the policy for the given chain
 */
void cmdPolicy()
{
  int nR;
  struct chain *c = NULL;

  if(strcmp(chain, "") == 0 || prgArgv[paramIndex] == NULL)
  {
    printf("us6tables: -P requires a chain and a policy\n");
    return;
  }
  if(strlen(chain) != 0)
  {
    for(nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        c = &shmFW->chains[nR];
    if(c == NULL)
    {
      printf("us6tables: Bad built-in chain name\n");
      return;
    }
  }

  if(c != NULL)
  {
    if(strcmp(prgArgv[paramIndex], "ACCEPT") == 0)
      c->policy = ACCEPT;
    else if(strcmp(prgArgv[paramIndex], "DROP") == 0)
      c->policy = DROP;
    else if(strcmp(prgArgv[paramIndex], "REJECT") == 0)
      c->policy = REJECT;
    else
      printf("us6tables: Bad policy name\n");
  }
}

/**
 * Create a new chain
 */
void cmdNewChain()
{
  struct chain c;

  if(strcmp(chain, "") == 0)
  {
    printf("us6tables: -N requires a chain\n");
    return;
  }
  if(strlen(chain) != 0)
  {
    memset(&c, 0, sizeof(struct chain));
    strcpy(c.name, chain);
    memcpy(&shmFW->chains[shmFW->nChains++], &c, sizeof(struct chain));
  }
}

/**
 * Delete the given chain
 */
void cmdDeleteChain()
{
  int nR, l, k, nRef, nC;

  if(strcmp(chain, "") == 0)
  {
    printf("us6tables: -X requires the name of the chain\n");
    return;
  }
  if(strlen(chain) != 0)
  {
    for(nC = -1, nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        nC = nR;
    if(nC == -1)
    {
      printf("us6tables: Bad built-in chain name\n");
      return;
    }
    else
    {
      if(shmFW->chains[nC].nRules != 0)
      {
        printf("us6tables: Directory not empty\n");
        return;
      }
      else
      {
        for(nRef = l = 0; l < shmFW->nChains; l++)
          for(k = 0; k < shmFW->chains[l].nRules; k++)
            if(shmFW->chains[l].rules[k].extraChainNumber == nC)
              nRef++;
        if(nRef != 0)
        {
          printf("us6tables: Too many links\n");
          return;
        }
        else
        {
          for(l = nC; l < shmFW->nChains - 1; l++)
            memcpy(&shmFW->chains[l], &shmFW->chains[l + 1], sizeof(struct chain));
          memset(&shmFW->chains[shmFW->nChains--], 0, sizeof(struct chain));
        }
      }
    }
  }
}

/**
 * Rename the given chain
 */
void cmdRenameChain()
{
  int nR;
  struct chain *c = NULL;

  if(strcmp(chain, "") == 0 || prgArgv[paramIndex] == NULL)
  {
    printf("us6tables: -E requires the old and the new name of the chain\n");
    return;
  }
  if(strlen(chain) != 0)
  {
    for(nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        c = &shmFW->chains[nR];
    if(c == NULL)
    {
      printf("us6tables: Bad built-in chain name\n");
      return;
    }
    else
      strcpy(c->name, prgArgv[paramIndex]);
  }
}
