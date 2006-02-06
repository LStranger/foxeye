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
LEAF *Find_Leaf (NODE *, const char *);
LEAF *Next_Leaf (NODE *, LEAF *, char **);
void Destroy_Tree (NODE **, void (*) (void *));
