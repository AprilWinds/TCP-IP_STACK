#ifndef _UTILS_H_
#define _UTILS_H_

#include<stddef.h>


typedef struct _list_head{
    struct _list_head* prev;
    struct _list_head* next;
}list_head_t;


static inline void list_init(list_head_t *list_head)
 {
  list_head->prev = list_head->next = list_head;
 }

 static inline void list_add_head(list_head_t *head, list_head_t *node)
 {
  node->next = head->next;
  node->prev = head;
 
  head->next->prev = node;
  head->next = node;
 }

 static inline void list_add_tail(list_head_t *head, list_head_t *node)
 {
  node->next = head;
  node->prev = head->prev;
 
  head->prev->next = node;
  head->prev = node;
 }
 static inline void list_add(list_head_t *prev, list_head_t *node)
 {
  node->next = prev->next;
  node->prev = prev;
 
  prev->next->prev = node;
  prev->next = node;
 }

 static inline void list_del(list_head_t *node)
 {
  node->prev->next = node->next;
  node->next->prev = node->prev;
 }

static inline int list_empty(list_head_t *list_head)
 {
  return (list_head->next == list_head && list_head->prev == list_head);
 }

static list_head_t *list_get_node(list_head_t *head)
 {
  if (list_empty(head))
      return NULL;
  else
      return head->next;
 }


#define container_of(ptr, type, member) ({               \
       const typeof( ((type *)0)->member )* __tptr = ptr;  \
       (type *)((char *)ptr - offsetof(type, member));     \
       })


typedef struct _queue {
  list_head_t head;
 } queue_t;

 inline void queue_init(queue_t *q)
 {
  list_init(&q->head);
 }
 
  inline int queue_empty(queue_t *q)
 {
  return list_empty(&q->head);
 }


 inline void enqueue(queue_t *qhead, queue_t *qnode)
 {
  list_add_tail(&qhead->head, &qnode->head);
 }
 
  inline queue_t *dequeue(queue_t *qhead){
    list_head_t *node = NULL;
    node = qhead->head.next;
    list_del(node);
    return container_of(node, queue_t, head);

 }




#endif