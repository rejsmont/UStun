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

#ifndef CLIST_H_
#define CLIST_H_

/**
 * Data structure for the list
 *
 * @var void *data               the data contained in the element
 * @var struct cList *next       next element
 * @var struct cList *prev       previous element
 */
struct cList
{
  void *data;
  struct cList *next;
  struct cList *prev;
};

/**
 * Creates a new list
 *
 * @return struct cList*         the pointer to the new created list
 */
struct cList *createCList(void);

/**
 * Add an element to the given list
 *
 * @param struct cList *list     the list to add to
 * @param void *data             the data of the element (content)
 */
void addToCList(struct cList *list, void *data);

/**
 * Delete an element from the given list
 *
 * @param struct cList *list     the list to delete from
 * @param struct cList *element  the element to be deleted
 * @return struct cList*         the pointer to the new list
 */
struct cList *deleteFromCList(struct cList *list, struct cList *element);

/**
 * Destroy a List
 *
 * @param struct cList *list     the list to be destroyed
 */
void destroyCList(struct cList *list);

/**
 * Run away all elements of the given list
 *
 * @param __cursor               the name of the variable used as cursor
 * @param __list                 the name of the variable containing the list
 */
#define foreachCList(__cursor, __list) for(__cursor = __list; __cursor != NULL; __cursor = __cursor->next)

#endif // CLIST_H_
