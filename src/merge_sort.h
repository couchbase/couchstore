/*
 *     Copyright 2024-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */
#pragma once

#include <array>
#include <forward_list>
#include <functional> // std::less
#include <optional>
#include <stdexcept>
#include <utility> // std::swap

namespace cb::couchstore {

/**
 * Sort Elements by sorting up to `block_size` at a time in memory and then
 * merging sorted runs. Elements are read from Stream objects which abstract
 * the storage mechanism.
 *
 * @param block_size Maximum number of elements to sort in memory
 * @param source Object to read items from for sorting
 * @param create_stream Functor which creates new Stream objects for storing
 *        Elements
 * @param read Functor to read an Element from a Stream
 * @param write Functor to write an Element to a Stream
 * @param rewind Functor to setup a Stream for reading Elements from its front
 * @param less Functor which compares two Elements and returns true if the first
 *        is strictly less than the second
 * @return Stream where Elements have been written in non-decreasing order
 */
template <typename Element,
          typename Stream,
          typename CreateStream,
          typename Read,
          typename Write,
          typename Rewind,
          typename Less = std::less<Element>>
Stream merge_sort(unsigned long long block_size,
                  Stream source,
                  CreateStream create_stream,
                  Read read,
                  Write write,
                  Rewind rewind,
                  Less less = {}) {
    struct Tape {
        Tape() = delete;

        Tape(const Tape&) = delete;

        explicit Tape(Stream&& stream) : stream(std::move(stream)) {
        }

        Tape(Tape&& other) : stream(std::move(other.stream)), size(other.size) {
        }

        void swap(Tape& other) {
            std::swap(stream, other.stream);
            std::swap(size, other.size);
        }

        std::optional<Element> pop(Read& read) {
            if (size == 0) {
                return {};
            }
            --size;
            return read(stream);
        }

        void push(Write& write, Element&& elem) {
            write(stream, std::move(elem));
            ++size;
        }

        Stream stream;
        unsigned long long size = 0;
    };

    rewind(source);

    std::array<Tape, 2> destination_tapes{Tape(create_stream()),
                                          Tape(create_stream())};

    bool continue_reading = true;
    int target_idx = 0;
    unsigned long long elems_count = 0;
    // Read a batch of Elements from the source into a list, sort the list and
    // write the elements to the destination_tapes, alternating between them for
    // each batch. Repeat until all source Elements are read.
    do {
        std::forward_list<Element> list;
        // std::forward_list does not track its size.
        std::size_t list_size = 0;
        do {
            std::optional<Element> elem = read(source);
            if (!elem) {
                continue_reading = false;
                break;
            }
            list.push_front(std::move(*elem));
            ++list_size;
        } while (list_size != block_size);
        if (list.empty()) {
            break;
        }
        list.sort(less);
        elems_count += list_size;
        do {
            destination_tapes[target_idx].push(write, std::move(list.front()));
            list.pop_front();
        } while (!list.empty());
        target_idx ^= 1;
    } while (continue_reading);

    // All elements read, we can free the source.
    { auto tmp = std::move(source); }

    if (elems_count <= block_size) {
        // We filled at most one block, so all elements are in the first tape.
        rewind(destination_tapes[0].stream);
        return std::move(destination_tapes[0].stream);
    }

    // Repeatedly merge blocks from the source_tapes to the destination_tapes.
    // for each pass the block size will double, and eventually all Elements
    // will be in one block.
    do {
        std::array<Tape, 2> source_tapes{Tape(create_stream()),
                                         Tape(create_stream())};
        source_tapes[0].swap(destination_tapes[0]);
        source_tapes[1].swap(destination_tapes[1]);
        rewind(source_tapes[0].stream);
        rewind(source_tapes[1].stream);

        /// Number of elements remaining in the source tapes,
        /// in the current block
        std::array<unsigned long long, 2> block_rem;
        std::optional<Element> left;
        std::optional<Element> right;
        /// Number of elements remaining to be processed in this pass
        auto elems_rem = elems_count;
        /// Total number of elements remaining in the destination tapes,
        /// in the current block
        unsigned long long dest_block_rem = 0;
        target_idx = 1;
        block_size *= 2;

        // Merge blocks from the two source tapes. The destination tape will
        // have all the Elements from the two source blocks, ordered. Repeat
        // until both source_tapes have been drained.
        do {
            if (dest_block_rem == 0) {
                // Filled a block, reset the elements remaining and switch tape.
                block_rem[0] = std::min(source_tapes[0].size, block_size / 2);
                block_rem[1] = std::min(source_tapes[1].size, block_size / 2);
                dest_block_rem = block_size;
                target_idx ^= 1;
            }
            if (block_rem[0] && !left) {
                left = source_tapes[0].pop(read);
                --block_rem[0];
            }
            if (block_rem[1] && !right) {
                right = source_tapes[1].pop(read);
                --block_rem[1];
            }
            if (left && right) {
                if (less(*right, *left)) {
                    destination_tapes[target_idx].push(write,
                                                       std::move(*right));
                    right.reset();
                } else {
                    destination_tapes[target_idx].push(write, std::move(*left));
                    left.reset();
                }
            } else if (left) {
                destination_tapes[target_idx].push(write, std::move(*left));
                left.reset();
            } else if (right) {
                destination_tapes[target_idx].push(write, std::move(*right));
                right.reset();
            } else {
                throw std::runtime_error(
                        "cb::couchstore::merge_sort: "
                        "EOF before all elements read");
            }
            --dest_block_rem;
        } while (--elems_rem);
        // When the block size is not less than the number of elements,
        // all the elements are in one tape, and we are done.
    } while (block_size < elems_count);

    // Be Kind, Rewind
    rewind(destination_tapes[target_idx].stream);
    return std::move(destination_tapes[target_idx].stream);
}

} // namespace cb::couchstore
