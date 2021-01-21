/* A Linked-List Memory Sort
   by Philip J. Erdelsky
   pje@efgh.com
   http://www.efgh.com/software/llmsort.htm
*/

#include "couchstore_config.h"
#include "mergesort.h"
#include <string.h>

void *sort_linked_list(void *p, unsigned idx,
                       int (*compare)(void *, void *, void *), void *pointer, unsigned long *pcount)
{
    unsigned base;
    unsigned long block_size;

    struct record {
        struct record *next[1];
        /* other members not directly accessed by this function */
    };

    struct tape {
        struct record *first, *last;
        unsigned long count;
    } tape[4];

    /* Distribute the records alternately to tape[0] and tape[1]. */

    memset(&tape, 0, sizeof(struct tape) * 4);
    base = 0;
    while (p != nullptr) {
        struct record *next = ((struct record *)p)->next[idx];
        ((struct record *)p)->next[idx] = tape[base].first;
        tape[base].first = ((struct record *)p);
        tape[base].count++;
        p = next;
        base ^= 1;
    }

    /* If the list is empty or contains only a single record, then */
    /* tape[1].count == 0L and this part is vacuous.               */

    for (base = 0, block_size = 1L; tape[base + 1].count != 0L;
            base ^= 2, block_size <<= 1) {
        int dest;
        struct tape *tape0, *tape1;
        tape0 = tape + base;
        tape1 = tape + base + 1;
        dest = base ^ 2;
        tape[dest].count = tape[dest + 1].count = 0;
        for (; tape0->count != 0; dest ^= 1) {
            unsigned long n0, n1;
            struct tape *output_tape = tape + dest;
            n0 = n1 = block_size;
            while (1) {
                struct record *chosen_record;
                struct tape *chosen_tape;
                if (n0 == 0 || tape0->count == 0) {
                    if (n1 == 0 || tape1->count == 0) {
                        break;
                    }
                    chosen_tape = tape1;
                    n1--;
                } else if (n1 == 0 || tape1->count == 0) {
                    chosen_tape = tape0;
                    n0--;
                } else if ((*compare)(tape0->first, tape1->first, pointer) > 0) {
                    chosen_tape = tape1;
                    n1--;
                } else {
                    chosen_tape = tape0;
                    n0--;
                }
                chosen_tape->count--;
                chosen_record = chosen_tape->first;
                chosen_tape->first = chosen_record->next[idx];
                if (output_tape->count == 0) {
                    output_tape->first = chosen_record;
                } else {
                    output_tape->last->next[idx] = chosen_record;
                }
                output_tape->last = chosen_record;
                output_tape->count++;
            }
        }
    }

    if (tape[base].count > 1L) {
        tape[base].last->next[idx] = nullptr;
    }
    if (pcount != nullptr) {
        *pcount = tape[base].count;
    }
    return tape[base].first;
}
