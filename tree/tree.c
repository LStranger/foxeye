/*
 * Copyright (C) 2000-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
 * 
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 * 
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 * 
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Tree-hash database indexing library.
 */ 

#include "tree.h"
#include <string.h>
#include <stdlib.h>

#define safe_calloc calloc
#define uchar unsigned char

/* prefix unprefixed leaf node by two chars */
static void tree_prefix_node (NODE *node)
{
  register int i;

  for (i = 0; i < node->num; i++)
    node->l[i].key += 2;
  node->mode |= TREE_PREF;
}

static unsigned char next00[2] = {0, 0};

static NODE *tree_depth_node (NODE *node)
{
  register NODE *that;
  register int n;

  that = safe_calloc (1, sizeof(NODE));
  memcpy (that->l, node->l, node->num * sizeof(LEAF));
  that->num = node->num;
  node->num = 1;
  that->mode = node->mode & ~TREE_PREF;		/* reset prefix flag */
  node->mode &= ~TREE_LEAF;			/* reset LEAF flag */
  if (!(node->mode & TREE_PREF))		/* if interval */
  {
    that->b[0] = node->b[0];
    that->b[1] = node->b[1];
  }
  node->l[0].s.n = that;
  that->parent = &node->l[0];
  for (n = 0; n < TREE_FULLNODE; n++)		/* set pointers to this leaf */
  {
    that->l[n].node = that;
    node->l[n].key = NULL;
  }
  if (!(that->mode & TREE_LEAF))		/* fix reverse pointers */
    for (n = 0; n < that->num; n++)
      that->l[n].s.n->parent = &that->l[n];
  return that;
}

// Проверка узла node на диапазон/префикс и корректировка ключей.
// next - символы начала следующего диапазона
static int tree_recheck_node (NODE *node, unsigned char *next)
{
  unsigned char last[2];

  last[0] = next[0];
  last[1] = next[1];
  if (last[1] == 0)
    last[0]--;
  last[1]--;
  if ((node->mode & TREE_PREF) || last[0] != node->b[0] || last[1] == 0 ||
      last[1] != node->b[1])
    return 0;					/* nothing more prefix */
  tree_prefix_node (node);
  return 0;
}

// Делит элемент ln в узле node (node is nodes node!) на две части.
// Возвращает количество добавленных листьев-узлов.
static int tree_split_node (NODE *node, int ln, unsigned char *next)
{
  register NODE *cur, *nrt = NULL;
  register int i;
  int n, r = 0;
  int sec;
  unsigned char *c;
  unsigned char *ch;
  unsigned char beg[2];				/* начало правого интервала */

  cur = node->l[ln].s.n;
  n = cur->num;
  if (cur->mode & TREE_PREF)			/* prefixed - just depth */
  {
    node = cur;
    cur = tree_depth_node (node);
    ln = 0;
    next = next00;
  }
  /* check first chars */
  if (cur->mode & TREE_LEAF)
  {
    for (i = 0; i < n && cur->l[i].key[0] == 0; i++);	/* count null keys */
    if (i == n)
      return 0;					/* the same keys - do nothing */
    ch = cur->l[(n-1)/2].key;			/* char for split */
  }
  else
    ch = cur->l[(n-1)/2].s.n->b;		/* char for split */
  /* select the point... */
  i = 0;
  if (cur->b[0] < next[0] - 1)			/* interval two chars or more */
  {							/* prefixed always is */
    sec = n;
    for (; i < n; i++)				/* first try one char... */
    {
      if (cur->mode & TREE_LEAF)
	c = cur->l[i].key;
      else
	c = cur->l[i].s.n->b;				/* got first char */
      if (sec > i && c[0] == ch[0])		/* at least one is that! */
	sec = i;				/* set to first found */
      else if (c[0] > ch[0])
	break;					/* the third interval */
    }
    if (sec >= n - i)				/* the third is worst? */
      i = sec;					/* set to second */
    if (i < 2 || n - i < 2)			/* it's dummy to split just 1 */
      i = 0;
    beg[1] = 0;
  }
  if (i != 0)					/* check first leaf */
  {
    if (!(cur->mode & TREE_LEAF))		/* have to syncronize it! */
      beg[1] = cur->l[i].s.n->b[1];
  }
  else						/* cannot split by one char */
  {
    sec = n;
    for (; i < n; i++)				/* try two chars... */
    {
      if (cur->mode & TREE_LEAF)
	c = cur->l[i].key;
      else
	c = cur->l[i].s.n->b;			/* got first chars */
      if (sec > i && c[0] == ch[0] && c[1] == ch[1]) /* at least one! */
	sec = i;				/* set to first found */
      else if (c[0] > ch[0] || (c[0] == ch[0] && c[1] > ch[1]))
	break;					/* the third interval */
    }
    if (sec >= n - i)				/* the third is worst? */
      i = sec;					/* set to second */
    if (cur->mode & TREE_LEAF)
      beg[1] = cur->l[i].key[1];
    else
      beg[1] = cur->l[i].s.n->b[1];			/* got second char */
  }
  if (cur->mode & TREE_LEAF)
    beg[0] = cur->l[i].key[0];
  else
    beg[0] = cur->l[i].s.n->b[0];			/* got first char */
  // i == 0 здесь, если два первых символа во всех элементах узла одинаковы
  // возможно только для TREE_LEAF!  :)
  if (i == 0)						/* serious trouble! */
  {					/* will try to depth the TREE_LEAF */
    if (ch[1] == 0)				/* have 2 chars or more? */
      return 0;					/* couldn't! */
    if ((cur->b[0] != beg[0] || cur->b[1] != beg[1]) && (ln == 0 ||
	(node->l[ln-1].s.n->mode & TREE_PREF)))	/* need empty at left? */
    {
      nrt = safe_calloc (1, sizeof(NODE));	/* new node */
      nrt->mode = TREE_LEAF;			/* empty node just leaf! */
      nrt->b[0] = cur->b[0];
      nrt->b[1] = cur->b[1];
      for (i = 0; i < TREE_FULLNODE; i++)
	nrt->l[i].node = nrt;			/* set reverse pointers */
      memmove (&node->l[ln+1], &node->l[ln], (node->num - ln) * sizeof(LEAF));
      node->l[ln].s.n = nrt;
      for (i = ln; i <= node->num; i++)		/* fix reverse pointers */
	node->l[i].s.n->parent = &node->l[i];
      node->num++;
      ln++;
      r++;
    }
    cur->b[0] = beg[0];
    cur->b[1] = beg[1];
    tree_prefix_node (cur);
    tree_split_node (node, ln, next);
    beg[1]++;
    if (beg[1] == 0)
      beg[0]++;
    if (ln+1 < node->num && !(node->l[ln+1].s.n->mode & TREE_PREF))
    {
      node->l[ln+1].s.n->b[0] = beg[0];		/* need empty at rigth? */
      node->l[ln+1].s.n->b[1] = beg[1];		/* just set new begin */
      return r;
    }
    if (beg[0] == next[0] && (beg[0] == 0 || beg[1] == next[1]))
      return r;					/* nothing to do */
    i = n = cur->num;				/* new will be empty */
  }
  nrt = safe_calloc (1, sizeof(NODE));		/* new node */
  if ((nrt->num = n - i))
  {
    memcpy (&nrt->l[0], &cur->l[i], nrt->num * sizeof(LEAF));
    nrt->mode = cur->mode;
  }
  else
    nrt->mode = TREE_LEAF;			/* empty node just leaf! */
  nrt->b[0] = beg[0];
  nrt->b[1] = beg[1];
  cur->num = i;					/* cut old node to i leaves */
  node->num++;
  ln++;
  r++;
  for (i = 0; i < TREE_FULLNODE; i++)
    nrt->l[i].node = nrt;			/* set reverse pointers */
  memmove (&node->l[ln+1], &node->l[ln], (node->num - ln) * sizeof(LEAF));
  node->l[ln].s.n = nrt;
  for (i = ln; i < node->num; i++)		/* fix reverse pointers */
    node->l[i].s.n->parent = &node->l[i];
  if (!(nrt->mode & TREE_LEAF))
    for (i = 0; i < nrt->num; i++)
      nrt->l[i].s.n->parent = &nrt->l[i];
  tree_recheck_node (cur, nrt->b);		/* get old node prefixed */
  tree_recheck_node (nrt, next);		/* get new node prefixed */
  return r;
}

/* attempt to do it faster */
static inline int local_strcmp (const unsigned char *s1, const unsigned char *s2)
{
  register const unsigned char *p1 = s1, *p2 = s2;

  while (*p1 == *p2)
  {
    if (*p1 == 0)
      break;
    p1++;
    if (*++p2 == 0)
      break;
    if (*p1 != *p2)
      break;
    p1++;
    p2++;
  }
  return (*p1 - *p2);
}

// Возвращает -1 при повторе ключа при uniq!=0, или число записей в узле.
// innext - два символа начала интервала следующего узла
static int tree_insert_leaf (NODE *node, const unsigned char *key,
		  void *data, int uniq, unsigned char *innext)
{
  register int i = 0;				/* iterator */
  int test;
  register NODE *cur = NULL;			/* to catch unexpected */
  unsigned char *next;

  if (node->mode & TREE_PREF)			/* prefix - increment */
  {
    key += 2;
    next = next00;				/* prefixed - interval 0...ff */
  }
  else
    next = innext;
  if (node->mode & TREE_LEAF)
  {
    if (node->num == TREE_FULLNODE)
      return -1;
    if (node->num > TREE_HALFNODE &&
	key[0] > node->l[TREE_HALFNODE].key[0])
      i = TREE_HALFNODE;
    for (; i < node->num; i++)			/* find the key next to it */
    {
      test = local_strcmp (node->l[i].key, key);
      if (test > 0)
	break;
      else if (uniq && test == 0)
	return -1;
    }
    if (i < node->num)
      memmove (&node->l[i+1], &node->l[i], (node->num - i) * sizeof(LEAF));
    node->num++;
    node->l[i].s.data = data;
    node->l[i].key = (uchar *)key;	/* node->l[i].node already set! */
  }
  else /* TREE_NODE */
  {
    if (node->num > TREE_HALFNODE &&
	key[0] > node->l[TREE_HALFNODE].s.n->b[0])
      i = TREE_HALFNODE;
    for (; i < node->num; i++)
    {
      cur = node->l[i].s.n;
      if (cur->b[0] > key[0] || (key[0] &&
	  cur->b[0] == key[0] && cur->b[1] > key[1]))
	break;
    }
    if (i < node->num)
      next = cur->b;
    i--;
    cur = node->l[i].s.n;
    if (tree_insert_leaf (cur, key, data, uniq, next) < 0)
      return -1;
    else if (cur->num >= TREE_FULLNODE-2)	/* 1 is reserve for node split */
      tree_split_node (node, i, next);
  }
  return node->num;
}

// Полный ключ key не должен изменяться или освобождаться,
// пока существует элемент в дереве, ассоциированный с ним.
// Возвращает 0 при нормальном выполнении, -1 при ошибке.
int Insert_Key (NODE **node, const char *key, void *data, int uniq)
{
  register int n;
  register NODE *cur;

  if (!node || !key)				/* error! no pointer! */
    return -1;
  if (!*node)					/* create a root node */
  {
    *node = cur = safe_calloc (1, sizeof(NODE));
    cur->mode = TREE_LEAF;			/* first root is leaf node */
    for (n = 0; n < TREE_FULLNODE; n++)
      cur->l[n].node = cur;
  }
  n = tree_insert_leaf (*node, (const unsigned char *)key, data, uniq, next00);
  if (n < TREE_FULLNODE-2)			/* inserted ok? */
    return n > 0 ? 0 : n;
  cur = tree_depth_node (*node);
  tree_split_node (*node, 0, next00);		/* we can split now! */
  return 0;					/* so just return */
}

// Удаляет элемент, возвращает 0 при удаче, -1 при неудаче
int Delete_Key (NODE *node, const char *key, void *data)
{
  register int i = 0;
  int n, r = -1;
  const unsigned char *k;
  register unsigned char *ch;

  if (node != NULL && key != NULL)
  {
    if (node->mode & TREE_PREF)			/* prefix - skip it */
      key += 2;
    k = key;
    if (node->mode & TREE_LEAF)
    {
      if (node->num > TREE_HALFNODE &&
	  k[0] > node->l[TREE_HALFNODE].key[0])
	i = TREE_HALFNODE;
      for (; i < node->num; i++)
      {
	n = local_strcmp (node->l[i].key, k);
	if (n == 0 && node->l[i].s.data == data)
	{
	  node->num--;
	  if (i < node->num)
	    memmove (&node->l[i], &node->l[i+1], (node->num - i) * sizeof(LEAF));
	  else
	    node->l[i].s.data = NULL;
	  r++;
	}
	else if (n > 0)
	  break;
      }
    }
    else /* TREE_NODE */
    {
      if (node->num > TREE_HALFNODE &&
	  k[0] > node->l[TREE_HALFNODE].s.n->b[0])
	i = TREE_HALFNODE;
      for (; i < node->num; i++)
      {
	ch = node->l[i].s.n->b;
	if (ch[0] > k[0] || (k[0] && ch[0] == k[0] && ch[1] > k[1]))
	  break;
      }
      if (i)
	return Delete_Key (node->l[i-1].s.n, key, data);
    }
  }
  return (r < 0) ? -1 : 0;
}

void Destroy_Tree (NODE **node, void (*destroy) (void *))
{
  register int i, n;

  if (node == NULL || *node == NULL)
    return;
  n = (*node)->num;
  if (!((*node)->mode & TREE_LEAF))
  {
    for (i = 0; i < n; i++)
      Destroy_Tree (&(*node)->l[i].s.n, destroy);
  }
  else if (destroy)
  {
    for (i = 0; i < n; i++)
      destroy ((*node)->l[i].s.data);
  }
  free (*node);
  *node = NULL;
}

// Находит первый подходящий ключ и возвращает соответствующий элемент
LEAF *Find_Leaf (NODE *node, const char *key, int exact)
{
  register int i = 0;
  int n;
  const unsigned char *k;
  register unsigned char *ch;

  if (node != NULL && key != NULL)
  {
    if (node->mode & TREE_PREF)			/* prefix - skip it */
      key += 2;
    k = key;
    if (node->mode & TREE_LEAF)
    {
      if (node->num > TREE_HALFNODE && k[0] > node->l[TREE_HALFNODE].key[0])
	i = TREE_HALFNODE;
      for (; i < node->num; i++)
      {
	n = local_strcmp (node->l[i].key, k);
	if (n == 0)
	  return &node->l[i];
	else if (n > 0)
	{
	  if (!exact)
	    return &node->l[i];
	  break;
	}
      }
    }
    else /* TREE_NODE */
    {
      if (node->num > TREE_HALFNODE && k[0] > node->l[TREE_HALFNODE].s.n->b[0])
	i = TREE_HALFNODE;
      for (; i < node->num; i++)
      {
	ch = node->l[i].s.n->b;
	if (ch[0] > k[0] || (k[0] && ch[0] == k[0] && ch[1] > k[1]))
	  break;
      }
      if (i)
	return Find_Leaf (node->l[i-1].s.n, key, exact);
    }
  }
  return NULL;
}

// Находит первый подходящий ключ и возвращает ассоциированные данные
void *Find_Key (NODE *node, const char *key)
{
  register LEAF *l = Find_Leaf (node, key, 1);
  return (l == NULL ? NULL : l->s.data);
}

static inline const char *_leaf_key (LEAF *l)
{
  register size_t i = 0;
  register NODE *n = l->node;

  for ( ; n; n = n->parent->node)
  {
    if (n->mode & TREE_PREF)
      i += 2;
    if (n->parent == NULL)
      break;				/* it's root node */
  }
  return (l->key - i);
}

const char *Leaf_Key (LEAF *l)
{
  return _leaf_key (l);
}

// Возвращает следующий элемент, или первый, если leaf равен NULL
// Если key не NULL, то помещает туда полное значение ключа
LEAF *Next_Leaf (NODE *node, LEAF *leaf, const char **key)
{
  register NODE *cur = node;
  ssize_t i;

  if (cur == NULL)
    return NULL;
  else if (leaf)
  {
    cur = leaf->node;
    i = leaf - &cur->l[0];
    if (i < 0 || i >= TREE_FULLNODE)
      return NULL;			/* no such leaf! */
    i++;
    if (i >= cur->num)			/* descent to parent */
      return (cur->parent ? Next_Leaf (node, cur->parent, key) : NULL);
    leaf = &cur->l[i];			/* try next node */
  }
  else
    leaf = cur->l;
  while (!(cur->mode & TREE_LEAF))	/* this is node, enter it */
  {
    cur = leaf->s.n;
    leaf = cur->l;
  }
  if (cur->num == 0)			/* fallback if empty node */
    return (cur->parent ? Next_Leaf (node, cur->parent, key) : NULL);
  if (key != NULL)
    *key = _leaf_key (leaf);
  return leaf;
}
