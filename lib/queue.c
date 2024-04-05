#include "queue.h"
#include "list.h"
#include <stdlib.h>
#include <assert.h>

struct queue
{
	list head;
	list tail;
	size_t size;
};

queue queue_create(void)
{
	queue q = malloc(sizeof(struct queue));
	q->head = q->tail = NULL;
	q->size = 0;
	return q;
}

int queue_empty(queue q)
{
	return q->head == NULL;
}

void queue_enq(queue q, void *element)
{
	if(queue_empty(q)) {
		q->head = q->tail = cons(element, NULL);
	} else {
		q->tail->next = cons(element, NULL);
		q->tail = q->tail->next;
	}
	q->size++;
}

void *queue_deq(queue q)
{
	assert(!queue_empty(q));
	{
		void *temp = q->head->element;
		q->head = cdr_and_free(q->head);
		q->size--;
		return temp;
	}
}

size_t get_queue_size(queue q)
{
	return q->size;
}