#include <stdio.h>
#include "tree.h"
#include <string.h>

static char buf[1024];
static char tr[1024];

static void print_node (NODE *node, char *c, char *t)
{
  register int i = 0;

  if (!node)
  {
    printf ("\n<NULL>\n");
    return;
  }
  if (node->mode & TREE_PREF)
  {
    *c++ = node->b[0];
    *c++ = node->b[1];
    printf (" +%c%c\n", node->b[0], node->b[1]);
  }
  else
    printf (" %c%c\n", node->b[0] ? node->b[0] : ' ', node->b[1] ? node->b[1] : ' ');
  if (node->mode & TREE_LEAF)
  {
    *c = 0;
    for (; i < node->num; i++)
    {
      printf (" \"%s%s\"", buf, node->l[i].key);
    }
    printf ("\n");
  }
  else
  {
    for (; i < node->num; i++)
    {
      sprintf (t, "->%d", i);
      printf ("Node %s:", tr);
      print_node (node->l[i].s.n, c, t + strlen(t));
    }
  }
}

void myprintf (char *c)
{
  printf ("\n %s", c);
}

int main ()
{
  NODE *node = NULL;
  LEAF *l = NULL;
  char *c, *ch;
  char last;
  int n = 0;
  FILE *fp;

  fp = fopen ("aaaa", "rb");
  while (fgets (buf, sizeof(buf), fp))
  {
//    printf ("\n");
    last = *buf;
    if (*buf == 0 || *buf == '\n')
      continue;
    for (c = buf; *c && last; c++)
    {
      ch = c;
      for (; *c && *c != '\n' && *c != ' ' && *c != '\t'; c++);
      last = *c;
      *c = 0;
      if (*ch == 0)
        continue;
      if (Insert_Key (&node, strdup (ch), &node, 1))
      {
//        printf (" <duplicate>\n");
//	printf (".");
      }
      else
      {
//        printf ("+");
	n++;
      }
    }
//    print_node (node, buf, tr);
//    printf ("\n");
  }
//  printf ("\nRoot node:");
//    print_node (node, buf, tr);
  printf ("-------\nИтого: %d слов\n...checking for find...", n);
  n = 0;
  while ((l = Next_Leaf (node, l, &c)))
  {
//    if (!strncmp (";РР", c, 3))
//      myprintf (c);
    if (Find_Key (node, c))
    {
      n++;
//      printf ("\t\tOK");
    }
  }
//  printf ("\n ...%d\n", n);
  printf (" %d\n...deleting...", n);
  n = 0;
  rewind (fp);
  while (fgets (buf, sizeof(buf), fp))
  {
    last = *buf;
    if (*buf == 0 || *buf == '\n')
      continue;
    for (c = buf; *c && last; c++)
    {
      ch = c;
      for (; *c && *c != '\n' && *c != ' ' && *c != '\t'; c++);
      last = *c;
      *c = 0;
      if (*ch == 0)
        continue;
      if (!Delete_Key (node, ch, &node))
	n++;
    }
  }
  printf (" %d\n", n);
//  Destroy_Tree (&node);
  return 0;
}
