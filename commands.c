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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
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
  int val;

  val = strtol(s, &p, 10);

  if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0))
    return 0;
  if(p == s)
    return 0;
  return 1;
}

void ust_error(const char* format, ...) {
    va_list args;
    fprintf( stderr, "us6tables: " );
    va_start( args, format );
    vfprintf( stderr, format, args );
    va_end( args );
    fprintf( stderr, "\n" );
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
        ust_error("unknown protocol `%s' specified", prgArgv[l + 1]);
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
          ust_error("error by parsing `%s' (not IPv6 address?)", addr);
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
          ust_error("invalid port/service `%s' specified", prgArgv[l + 1]);
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
          ust_error("error by parsing `%s' (not IPv6 address?)", addr);
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
          ust_error("invalid port/service `%s' specified", prgArgv[l + 1]);
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
      else if(strcmp(prgArgv[l + 1], "RETURN") == 0)
        rule->action = RETURN;
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
          ust_error("unknown target `%s'", prgArgv[l + 1]);
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
              ust_error("Unknown arg `--comment'");
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
          ust_error("COMMENT match: You must specify `--comment'");
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
              ust_error("Unknown arg `--state'");
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
          ust_error("You must specify `--state'");
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
              ust_error("Unknown arg `--source-ports'");
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
                    ust_error("invalid port/service `%s' specified", t);
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
              ust_error("Unknown arg `--destination-ports'");
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
                    ust_error("invalid port/service `%s' specified", t);
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
              ust_error("Unknown arg `--ports'");
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
                    ust_error("invalid port/service `%s' specified", t);
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
          ust_error("You must specify `--ports | --destination-ports | --source-ports'");
          return NULL;
        }
      }
      else
      {
        ust_error("unknown module `%s'", prgArgv[l + 1]);
        return NULL;
      }
      l = endMatch + 1;
    }
    else
    {
      ust_error("unrecognized parameter `%s'", prgArgv[l]);
      return NULL;
    }
  }

  if((rule->action == NONE) && (rule->extraChainNumber == -1))
  {
    ust_error("no action specified");
    return NULL;
  }
  return rule;
}

/**
 * Append a rule to the given chain
 */
int cmdAppend()
{
  int nR;
  struct chain *c = NULL;
  struct fwRule *rule;

  if(strcmp(chain, "") == 0)
  {
    ust_error("option \"-A\" requires an argument");
    return 2;
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0)
      c = &shmFW->chains[nR];
  if(c == NULL)
  {
    if(strcmp(chain, "FORWARD") != 0) {
      ust_error("No chain/target/match by that name.");
      return 1;
    } else {
      return 0;
    }
  }
  if(c->nRules < MAX_RULES_NUM)
  {
    rule = getRuleDescription();
    if(rule != NULL)
    {
      memcpy(&c->rules[c->nRules], rule, sizeof(struct fwRule));
      c->nRules++;
      free(rule);
    } else {
      return 5;
    }
  }
  else
  {
    ust_error("No space left in memory");
    return 5;
  }
  return 0;
}

/**
 * Delete a rule from the given chain
 */
int cmdDelete()
{
  int nC, nR, l;
  struct chain *c = NULL;
  char *e;
  struct fwRule *rule;

  if(strcmp(chain, "") == 0)
  {
    ust_error("option \"-D\" requires an argument");
    return 2;
  }
  for(nC = 0; nC < shmFW->nChains; nC++)
    if(strcmp(chain, shmFW->chains[nC].name) == 0)
      c = &shmFW->chains[nC];
  if(c == NULL)
  {
    if(strcmp(chain, "FORWARD") != 0) {
      ust_error("No chain/target/match by that name.");
      return 1;
    } else {
      return 0;
    }
  }

  l = strtol(prgArgv[paramIndex],&e,10) - 1;
  if ((errno != 0 && l == -1)||(prgArgv[paramIndex] == e)) {
    rule = getRuleDescription();
    if (rule != NULL)
      for(nR = 0; nR < c->nRules; nR++) {
        if (memcmp(&c->rules[nR], rule, sizeof(struct fwRule)) == 0) {
          l = nR;
          break;
        }
      }
    else {
      ust_error("Bad rule (does a matching rule exist in that chain?).");
      return 1;
    }
  }
  if (l >= c->nRules) {
    ust_error("Index of deletion too big.");
    return 1;
  }
  if (l <= 0) {
    ust_error("Invalid rule number `%d'.",l+1);
    return 1;
  }
  for(nR = l; nR < c->nRules - 1; nR++)
    memcpy(&c->rules[nR], &c->rules[nR + 1], sizeof(struct fwRule));
  memset(&c->rules[c->nRules], 0, sizeof(struct fwRule));
  c->nRules--;
  return 0;
}

/**
 * Insert a rule to the given chain at the given position
 */
int cmdInsert()
{
  int nC, nR, l;
  struct chain *c = NULL;
  char *e;
  struct fwRule *rule;

  if(strcmp(chain, "") == 0)
  {
    ust_error("option \"-I\" requires an argument");
    return 2;
  }
  for(nC = 0; nC < shmFW->nChains; nC++)
    if(strcmp(chain, shmFW->chains[nC].name) == 0)
      c = &shmFW->chains[nC];
  if(c == NULL)
  {
    if(strcmp(chain, "FORWARD") != 0) {
      ust_error("No chain/target/match by that name.");
      return 1;
    } else {
      return 0;
    }
  }

  nR = strtol(prgArgv[paramIndex],&e,10) - 1;
  if ((errno != 0 && nR == -1)||(prgArgv[paramIndex] == e))
    nR = 0;
  else
    paramIndex++;

  if((nR > c->nRules)||(nR < 0))
  {
    ust_error("Invalid rule number `%d'.",nR+1);
    return 1;
  }
  if((c->nRules + 1) >= MAX_RULES_NUM)
  {
    ust_error("No space left in memory");
    return 1;
  }

  rule = getRuleDescription();
  if((rule != NULL)&&(rule->action != RETURN))
  {
    for(l = c->nRules - 1; l >= nR; l--) {
      memcpy(&c->rules[l + 1], &c->rules[l], sizeof(struct fwRule));
    }
    memcpy(&c->rules[nR], rule, sizeof(struct fwRule));
    c->nRules++;
    free(rule);
  } else {
    return 1;
  }
  return 0;
}

/**
 * Replace a rule from the given chain
 */
int cmdReplace()
{
  int nR;
  struct chain *c = NULL;
  struct fwRule *rule;

  if(strcmp(chain, "") == 0 || prgArgv[paramIndex] == NULL)
  {
    ust_error("option \"-R\" requires an argument");
    return 2;
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0)
      c = &shmFW->chains[nR];
  if(c == NULL)
  {
    if(strcmp(chain, "FORWARD") != 0) {
      ust_error("No chain/target/match by that name.");
      return 1;
    } else {
      return 0;
    }
  }
  nR = atoi(prgArgv[paramIndex]) - 1;   // Rules saved 0-based, but displayed 1-based
  if(nR > c->nRules)
  {
    ust_error("Invalid rule number `%d'.",nR+1);
    return 1;
  }
  paramIndex++;
  rule = getRuleDescription();
  if(rule != NULL)
  {
    memcpy(&c->rules[nR], rule, sizeof(struct fwRule));
    free(rule);
  } else {
    return 5;
  }
  return 0;
}

/**
 * List the rules (if given, just from given chain)
 */
int cmdList()
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
      ust_error("No chain/target/match by that name");
      return 1;
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
        printf("Chain %s (%d references, %d rules)\n",
          shmFW->chains[nR].name,
          nRef,
          shmFW->chains[nR].nRules);
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
  return 0;
}

/**
 * Flush all rules (if given, just from given chain)
 */
int cmdFlush()
{
  int l, nR;

  if(strlen(chain) != 0)
  {
    for(l = -1, nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        l = nR;
    if(l == -1)
    {
      ust_error("No chain/target/match by that name");
      return 1;
    }
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0 || strlen(chain) == 0)
    {
      shmFW->chains[nR].nRules = 0;
      memset(shmFW->chains[nR].rules, 0, sizeof(struct fwRule) * MAX_RULES_NUM);
    }
  return 0;
}

/**
 * Zeros the packet count (if given, just from given chain)
 */
int cmdZero()
{
  int l, nR;

  if(strlen(chain) != 0)
  {
    for(l = -1, nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        l = nR;
    if(l == -1)
    {
      ust_error("No chain/target/match by that name");
      return 1;
    }
  }
  for(nR = 0; nR < shmFW->nChains; nR++)
    if(strcmp(chain, shmFW->chains[nR].name) == 0 || strlen(chain) == 0)
    {
      shmFW->chains[nR].nPackets = 0;
      shmFW->chains[nR].nBytes = 0;
    }
  return 0;
}

/**
 * Set the policy for the given chain
 */
int cmdPolicy()
{
  int nR;
  struct chain *c = NULL;

  if(strcmp(chain, "") == 0 || prgArgv[paramIndex] == NULL)
  {
    ust_error("option \"-P\" requires an argument");
    return 2;
  }
  if(strlen(chain) != 0)
  {
    for(nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        c = &shmFW->chains[nR];
    if(c == NULL)
    {
      if(strcmp(chain, "FORWARD") != 0) {
        ust_error("No chain/target/match by that name");
        return 1;
      } else {
        return 0;
      }
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
    else {
      ust_error("Bad policy name");
      return 5;
    }
  }
  
  return 0;
}

/**
 * Create a new chain
 */
int cmdNewChain()
{
  int nR;
  struct chain c;
  struct chain *e = NULL;

  if(strcmp(chain, "") == 0)
  {
    ust_error("option \"-N\" requires an argument");
    return 2;
  }
  if(strlen(chain) != 0)
  {
    for(nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        e = &shmFW->chains[nR];
    if(e != NULL)
    {
      ust_error("Chain already exists.");
      return 1;
    }
    else
    {
      memset(&c, 0, sizeof(struct chain));
      strcpy(c.name, chain);
      memcpy(&shmFW->chains[shmFW->nChains++], &c, sizeof(struct chain));
    }
  }
  
  return 0;
}

/**
 * Delete the given chain
 */
int cmdDeleteChain()
{
  int nR, l, k, nRef, nC;

  for(nC = -1, nR = 0; nR < shmFW->nChains; nR++)
    if((strcmp(chain, shmFW->chains[nR].name) == 0) || ((strlen(chain) == 0)&&(strcmp("INPUT", shmFW->chains[nR].name) != 0)&&(strcmp("OUTPUT", shmFW->chains[nR].name) != 0)))
    {
      nC = nR;
      if(shmFW->chains[nC].nRules != 0)
      {
        ust_error("Directory not empty");
        return 1;
      }
      else
      {
        for(nRef = l = 0; l < shmFW->nChains; l++)
          for(k = 0; k < shmFW->chains[l].nRules; k++)
            if(shmFW->chains[l].rules[k].extraChainNumber == nC)
              nRef++;
        if(nRef != 0)
        {
          ust_error("Too many links");
          return 1;
        }
        else
        {
          for(l = nC; l < shmFW->nChains - 1; l++)
            memcpy(&shmFW->chains[l], &shmFW->chains[l + 1], sizeof(struct chain));
          memset(&shmFW->chains[shmFW->nChains--], 0, sizeof(struct chain));
          nR--;
        }
      }
    }
  
  if(nC == -1)
  {
    ust_error("No chain/target/match by that name");
    return 1;
  }
  return 0;
}

/**
 * Rename the given chain
 */
int cmdRenameChain()
{
  int nR;
  struct chain *c = NULL;

  if(strcmp(chain, "") == 0 || prgArgv[paramIndex] == NULL)
  {
    ust_error("option \"-E\" requires an argument");
    return 2;
  }
  if(strlen(chain) != 0)
  {
    for(nR = 0; nR < shmFW->nChains; nR++)
      if(strcmp(chain, shmFW->chains[nR].name) == 0)
        c = &shmFW->chains[nR];
      if(c == NULL)
      {
        ust_error("No chain/target/match by that name");
        return 1;
      }
      else
        strcpy(c->name, prgArgv[paramIndex]);
  }
  return 0;
}

