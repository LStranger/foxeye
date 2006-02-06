#define TREE_LEAF 1
#define TREE_PREF 2

// TREE_FULLNODE должно помещаться в unsigned char (т.е. < 255),
// кроме того, не должно быть сильно большим. IMHO, оптимально - 16.
// Но повторяющихся ключей не может быть больше, чем TREE_FULLNODE!
#define TREE_HALFNODE 12
#define TREE_FULLNODE 2*TREE_HALFNODE
//#define TREE_NOSPLIT_MAX 5
//#define TREE_CANCONNECT 11

typedef struct LEAF
{
  union {
    void *data;		// Ассоциированные данные
    struct NODE *n;
  } s;
  unsigned char *key;	// Частичное значение ключа
  struct NODE *node;	// Узел, в котором этот элемент
} LEAF;

typedef struct NODE
{
  unsigned char b[2];	// Начало диапазона или часть ключа (префикс)
//  unsigned char e[2];	// Конец диапазона или NULL
  unsigned char mode;	// Тип блока
  unsigned char num;	// Количество занятых элементов в блоке
  struct LEAF *parent;	// Указатель на лист, в котором мы находимся
  struct LEAF l[TREE_FULLNODE];	// Блок элементов
} NODE;

int Insert_Key (NODE **, const char *, void *, int);
void *Find_Key (NODE *, const char *);
int Delete_Key (NODE *, const char *, void *);
LEAF *Find_Leaf (NODE *, const char *);
LEAF *Next_Leaf (NODE *, LEAF *, char **);
void Destroy_Tree (NODE **, void (*) (void *));
