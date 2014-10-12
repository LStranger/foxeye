/*
 * Copyright (C) 2000-2010  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Tree-hash database indexing library.
 */

#define TREE_LEAF 1
#define TREE_PREF 2

// TREE_FULLNODE ������ ���������� � unsigned char (�.�. < 255),
// ����� ����, �� ������ ���� ������ �������. IMHO, ���������� - 16.
// �� ������������� ������ �� ����� ���� ������, ��� TREE_FULLNODE!
#define TREE_HALFNODE 12
#define TREE_FULLNODE 2*TREE_HALFNODE
//#define TREE_NOSPLIT_MAX 5
//#define TREE_CANCONNECT 11

typedef struct LEAF
{
  union {
    void *data;		// ��������������� ������
    struct NODE *n;
  } s;
  unsigned char *key;	// ��������� �������� �����
  struct NODE *node;	// ����, � ������� ���� �������
} LEAF;

typedef struct NODE
{
  unsigned char b[2];	// ������ ��������� ��� ����� ����� (�������)
//  unsigned char e[2];	// ����� ��������� ��� NULL
  unsigned char mode;	// ��� �����
  unsigned char num;	// ���������� ������� ��������� � �����
  struct LEAF *parent;	// ��������� �� ����, � ������� �� ���������
  struct LEAF l[TREE_FULLNODE];	// ���� ���������
} NODE;

int Insert_Key (NODE **, const char *, void *, int);
void *Find_Key (NODE *, const char *);
int Delete_Key (NODE *, const char *, void *);
LEAF *Find_Leaf (NODE *, const char *, int);
LEAF *Next_Leaf (NODE *, LEAF *, const char **);
const char *Leaf_Key (LEAF *);
void Destroy_Tree (NODE **, void (*) (void *));
