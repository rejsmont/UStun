/*******************************************************************************
*    Dynamic list in C                                                         *
*    Copyright (C) 2011-averyfarwaydate Luca Bertoncello                       *
*    Hartigstrasse, 12 - 01127 Dresden Deutschland                             *
*    E-Mail: lucabert@lucabert.de, lucabert@lucabert.com                       *
*    http://www.lucabert.de/  http://www.lucabert.com/                         *
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
#include "incs/clist.h"

/**
 * Creates a new list
 *
 * @return struct cList*         the pointer to the new created list
 */
struct cList *createCList()
{
  struct cList *l;

  l = malloc(sizeof(struct cList));
  l->prev = l->next = NULL;
  l->data = NULL;

  return(l);
}

/**
 * Add an element to the given list
 *
 * @param struct cList *list     the list to add to
 * @param void *data             the data of the element (content)
 */
void addToCList(struct cList *list, void *data)
{
  struct cList *l, *n;

  if(list->data == NULL) // first insert
    list->data = data;
  else
  {
    l = list;
    while(l->next != NULL)
      l = l->next;
    n = malloc(sizeof(struct cList));
    n->data = data;
    n->next = NULL;
    n->prev = l;
    l->next = n;
  }
}

/**
 * Delete an element from the given list
 *
 * @param struct cList *list     the list to delete from
 * @param struct cList *element  the element to be deleted
 * @return struct cList*         the pointer to the new list
 */
struct cList *deleteFromCList(struct cList *list, struct cList *element)
{
  struct cList *p, *n;

  free(element->data);
  p = element->prev;
  n = element->next;
  free(element);

  if(p != NULL)
    p->next = n;
  else
    list = n;
  if(n != NULL)
    n->prev = p;

  return(list);
}

/**
 * Destroy a List
 *
 * @param struct cList *list     the list to be destroyed
 */
void destroyCList(struct cList *list)
{
  struct cList *l, *n;

  l = list;
  while(l != NULL)
  {
    n = l->next;
    free(l->data);
    free(l);
    l = n;
  }
}
