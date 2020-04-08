/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * @copyright 2013 Couchbase, Inc.
 *
 * @author Filipe Manana  <filipe@couchbase.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 **/

#include "sorted_list.h"
#include <platform/cb_malloc.h>
#include <platform/cbassert.h>
#include <stdlib.h>
#include <string.h>

typedef struct sorted_list_node_t {
    void* element;
    struct sorted_list_node_t* next;
} sorted_list_node_t;

typedef struct {
    sorted_list_cmp_t cmp_fun;
    sorted_list_node_t* head;
    int length;
} sorted_list_t;

typedef struct {
    sorted_list_node_t* current;
} sorted_list_iterator_t;

void* sorted_list_create(sorted_list_cmp_t cmp_fun) {
    sorted_list_t* list = (sorted_list_t*)cb_malloc(sizeof(sorted_list_t));

    if (list != NULL) {
        list->cmp_fun = cmp_fun;
        list->head = NULL;
        list->length = 0;
    }

    return (void*)list;
}

int sorted_list_add(void* list, const void* elem, size_t elem_size) {
    sorted_list_t* l = (sorted_list_t*)list;
    sorted_list_node_t* n = l->head;
    sorted_list_node_t* prev = NULL;
    sorted_list_node_t* new_node;
    int cmp = 0;

    new_node = (sorted_list_node_t*)cb_malloc(sizeof(sorted_list_node_t));
    if (new_node == NULL) {
        return -1;
    }
    new_node->element = cb_malloc(elem_size);
    if (new_node->element == NULL) {
        cb_free(new_node);
        return -1;
    }
    memcpy(new_node->element, elem, elem_size);

    if (l->head == NULL) {
        new_node->next = NULL;
        l->head = new_node;
        l->length += 1;
        return 0;
    }

    while (n != NULL) {
        cmp = l->cmp_fun(n->element, elem);
        if (cmp >= 0) {
            break;
        }
        prev = n;
        n = n->next;
    }

    if (prev != NULL) {
        prev->next = new_node;
    } else {
        l->head = new_node;
    }

    if (cmp == 0) {
        new_node->next = n->next;
        cb_free(n->element);
        cb_free(n);
    } else {
        l->length += 1;
        new_node->next = n;
    }

    return 0;
}

void* sorted_list_get(const void* list, const void* elem) {
    const sorted_list_t* l = (const sorted_list_t*)list;
    sorted_list_node_t* n = l->head;
    int cmp;

    while (n != NULL) {
        cmp = l->cmp_fun(n->element, elem);
        if (cmp == 0) {
            return n->element;
        } else if (cmp > 0) {
            return NULL;
        } else {
            n = n->next;
        }
    }

    return n;
}

void sorted_list_remove(void* list, const void* elem) {
    sorted_list_t* l = (sorted_list_t*)list;
    sorted_list_node_t* n = l->head;
    sorted_list_node_t* prev = NULL;
    int cmp;

    while (n != NULL) {
        cmp = l->cmp_fun(n->element, elem);
        if (cmp == 0) {
            if (prev == NULL) {
                cb_assert(n == l->head);
                l->head = n->next;
            } else {
                prev->next = n->next;
            }
            l->length -= 1;
            cb_free(n->element);
            cb_free(n);
            break;
        } else if (cmp > 0) {
            return;
        } else {
            prev = n;
            n = n->next;
        }
    }
}

void sorted_list_free(void* list) {
    sorted_list_t* l = (sorted_list_t*)list;
    sorted_list_node_t* n = NULL;

    if (l != NULL) {
        while (l->head != NULL) {
            n = l->head;
            l->head = l->head->next;
            cb_free(n->element);
            cb_free(n);
        }
        cb_free(list);
    }
}

int sorted_list_size(const void* list) {
    const sorted_list_t* l = (const sorted_list_t*)list;

    return l->length;
}

void* sorted_list_iterator(const void* list) {
    const sorted_list_t* l = (const sorted_list_t*)list;
    sorted_list_iterator_t* it = NULL;

    it = (sorted_list_iterator_t*)cb_malloc(sizeof(*it));
    if (it != NULL) {
        it->current = l->head;
    }

    return (void*)it;
}

void* sorted_list_next(void* iterator) {
    sorted_list_iterator_t* it = (sorted_list_iterator_t*)iterator;
    void* elem = NULL;

    if (it->current != NULL) {
        elem = it->current->element;
        it->current = it->current->next;
    }

    return elem;
}

void sorted_list_free_iterator(void* iterator) {
    cb_free(iterator);
}
