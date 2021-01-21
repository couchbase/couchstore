/*
**  arena.h
**  couchstore
**
**  Created by Jens Alfke on 4/13/12.
**  Copyright (c) 2012 Couchbase, Inc. All rights reserved.
*/

#pragma once

#include <sys/types.h>

/** Opaque arena-allocator object. */
struct arena;

/** Saved position/state of an arena. */
struct arena_position;

/**
 * Creates a new arena allocator.
 * @param chunk_size The size of the memory blocks the allocator sub-allocates from malloc. Pass 0 for the default (32kbytes).
 * @return The new arena object.
 */
arena* new_arena(size_t chunk_size);

/**
 * Deletes an arena and all of its memory allocations.
 */
void delete_arena(arena*);

/**
 * Allocates memory from an arena.
 * @param arena The arena to allocate from
 * @param size The number of bytes to allocate
 * @return A pointer to the allocated block, or NULL on failure.
 */
void* arena_alloc(arena*, size_t size);

/**
 * Allocates unaligned memory from an arena.
 * Saves a couple of bytes if your block doesn't need to be word-aligned.
 */
void* arena_alloc_unaligned(arena* a, size_t size);

/**
 * "Frees" a block allocated from an arena. This actually doesn't do anything.
 * In a debug build it at least checks that the pointers was (probably) allocated from the arena.
 * In a release build it's explicitly an inlined no-op and there's no need to call it at all.
 */
void arena_free(arena*, void*);

/**
 * Captures the current state of an arena, i.e. which blocks have been allocated.
 * Save the return value and pass it to arena_free_from_mark later to free all blocks allocated
 * since this point.
 */
const arena_position* arena_mark(arena *a);

/**
 * Frees all blocks from the arena that have been allocated since the corresponding call to
 * arena_mark. (The mark remains valid and can be used again.)
 */
void arena_free_from_mark(arena *a, const arena_position *mark);

/**
 * Frees all blocks from the arena.
 */
void arena_free_all(arena *a);
