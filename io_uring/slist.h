#ifndef INTERNAL_IO_SLIST_H
#define INTERNAL_IO_SLIST_H

#include <linux/io_uring_types.h>

/*
 * Macro to iterate through all nodes in the list
 * @pos: current node (iterator)
 * @head: list head to iterate over
 */
#define __wq_list_for_each(pos, head)              \
    for (pos = (head)->first; pos; pos = (pos)->next)

/*
 * Macro to iterate through all nodes with previous node tracking
 * @pos: current node (iterator)
 * @prv: previous node
 * @head: list head to iterate over
 */
#define wq_list_for_each(pos, prv, head)           \
    for (pos = (head)->first, prv = NULL; pos; prv = pos, pos = (pos)->next)

/*
 * Macro to continue iteration from current position
 * @pos: current node (iterator)
 * @prv: previous node
 */
#define wq_list_for_each_resume(pos, prv)          \
    for (; pos; prv = pos, pos = (pos)->next)

/*
 * Check if list is empty
 * @list: list to check
 */
#define wq_list_empty(list) (READ_ONCE((list)->first) == NULL)

/*
 * Initialize an empty list
 * @list: list to initialize
 */
#define INIT_WQ_LIST(list) do {                    \
    (list)->first = NULL;                          \
} while (0)

/*
 * Add node after specified position in the list
 * @node: node to add
 * @pos: node after which to add
 * @list: list to modify
 */
static inline void wq_list_add_after(struct io_wq_work_node *node,
                     struct io_wq_work_node *pos,
                     struct io_wq_work_list *list)
{
    struct io_wq_work_node *next = pos->next;

    pos->next = node;
    node->next = next;
    if (!next)
        list->last = node;
}

/*
 * Add node at the tail of the list
 * @node: node to add
 * @list: list to modify
 */
static inline void wq_list_add_tail(struct io_wq_work_node *node,
                    struct io_wq_work_list *list)
{
    node->next = NULL;
    if (!list->first) {
        list->last = node;
        WRITE_ONCE(list->first, node);
    } else {
        list->last->next = node;
        list->last = node;
    }
}

/*
 * Add node at the head of the list
 * @node: node to add
 * @list: list to modify
 */
static inline void wq_list_add_head(struct io_wq_work_node *node,
                    struct io_wq_work_list *list)
{
    node->next = list->first;
    if (!node->next)
        list->last = node;
    WRITE_ONCE(list->first, node);
}

/*
 * Cut the list after specified node
 * @list: list to modify
 * @last: last node to keep in original list
 * @prev: node before the cut point (NULL if cutting at head)
 */
static inline void wq_list_cut(struct io_wq_work_list *list,
                   struct io_wq_work_node *last,
                   struct io_wq_work_node *prev)
{
    /* first in the list, if prev==NULL */
    if (!prev)
        WRITE_ONCE(list->first, last->next);
    else
        prev->next = last->next;

    if (last == list->last)
        list->last = prev;
    last->next = NULL;
}

/*
 * Internal function to splice one list into another
 * @list: list to splice
 * @to: node after which to splice
 */
static inline void __wq_list_splice(struct io_wq_work_list *list,
                    struct io_wq_work_node *to)
{
    list->last->next = to->next;
    to->next = list->first;
    INIT_WQ_LIST(list);
}

/*
 * Splice one list into another after specified node
 * @list: list to splice
 * @to: node after which to splice
 * Returns true if list was non-empty and spliced
 */
static inline bool wq_list_splice(struct io_wq_work_list *list,
                  struct io_wq_work_node *to)
{
    if (!wq_list_empty(list)) {
        __wq_list_splice(list, to);
        return true;
    }
    return false;
}

/*
 * Add node to the head of a stack (LIFO)
 * @node: node to add
 * @stack: stack to modify
 */
static inline void wq_stack_add_head(struct io_wq_work_node *node,
                     struct io_wq_work_node *stack)
{
    node->next = stack->next;
    stack->next = node;
}

/*
 * Delete node from list
 * @list: list to modify
 * @node: node to delete
 * @prev: previous node (NULL if deleting head)
 */
static inline void wq_list_del(struct io_wq_work_list *list,
                   struct io_wq_work_node *node,
                   struct io_wq_work_node *prev)
{
    wq_list_cut(list, node, prev);
}

/*
 * Extract next node from stack (LIFO)
 * Returns extracted node
 */
static inline struct io_wq_work_node *wq_stack_extract(struct io_wq_work_node *stack)
{
    struct io_wq_work_node *node = stack->next;

    stack->next = node->next;
    return node;
}

/*
 * Get next work item in the list
 * Returns next work item or NULL if at end
 */
static inline struct io_wq_work *wq_next_work(struct io_wq_work *work)
{
    if (!work->list.next)
        return NULL;

    return container_of(work->list.next, struct io_wq_work, list);
}

#endif // INTERNAL_IO_SLIST_H