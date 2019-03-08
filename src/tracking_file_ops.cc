/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2017 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "config.h"

#include "tracking_file_ops.h"

#include <inttypes.h>
#include <array>
#include <cctype>
#include <iostream>
#include <string>
#include <vector>

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define ANSI_256COLOR_BG_GREY "\x1b[48;5;240m"

class TrackingFileOps::File {
public:
    // Similar to Couchstore's FileTag; except breaks out the different
    // B-Tree types into their own values.
    enum class BlockTag : uint8_t {
        Empty, // Ignore this access; speculative (e.g. searching for header).
        FileHeader, // File header.
        BTreeById,
        BTreeBySequence,
        BTreeByLocal,
        Document, // User document data.
        Unknown, // Valid access, but unknown what for.
    };

    // Information for each block of the file.
    struct BlockInfo {
        BlockInfo() = default;
        BlockInfo(BlockTag tag, bool historic = false)
            : accessSize(1), tag(tag), historic(historic) {
        }

        /// Size of currently tagged access.
        size_t accessSize = 0;

        BlockTag tag = BlockTag::Empty;
        bool historic = false;

        std::string to_string();

        bool isFull() {
            return accessSize == blockSize;
        }
    };

    File(couchstore_error_info_t* errinfo);
    ~File();

    void setCurrentTag(FileTag tag) {
        currentTag = tag;
    }

    void setCurrentTree(Tree tree) {
        currentTree = tree;
    }

    void setHistoricData(bool historic) {
        currentHistoric = historic;
    }
    void recordAccess(cs_off_t offset, size_t size);

    static std::string to_string(BlockTag tag);

    /// The granularity at which we track the file (in bytes).
    static const size_t blockSize = 64;

    /// Handle of the underlying file ops interface.
    couch_file_handle handle;

protected:
    static BlockTag encodeTag(FileTag currentTag, Tree currentTree);

    // State machine for couchstore file access

    /// The type of data which is currently being accessed.
    FileTag currentTag = FileTag::Unknown;
    /// The particular tree which is currently being accessed.
    Tree currentTree = Tree::Unknown;
    /// Are we currently accessing historic (old) data?
    bool currentHistoric = false;

    /// Vector of blockInfos, indexed by the file block number.
    std::vector<BlockInfo> blockInfo;
};

const size_t TrackingFileOps::File::blockSize;

couch_file_handle TrackingFileOps::constructor(
        couchstore_error_info_t* errinfo) {
    auto* file = new File(errinfo);
    return reinterpret_cast<couch_file_handle>(file);
}

couchstore_error_t TrackingFileOps::open(couchstore_error_info_t* errinfo,
                                         couch_file_handle* handle,
                                         const char* path,
                                         int oflag) {
    auto* file = reinterpret_cast<File*>(*handle);
    return couchstore_get_default_file_ops()->open(
            errinfo, &file->handle, path, oflag);
}

couchstore_error_t TrackingFileOps::close(couchstore_error_info_t* errinfo,
                                          couch_file_handle handle) {
    auto* file = reinterpret_cast<File*>(handle);
    if (file == nullptr) {
        return COUCHSTORE_ERROR_INVALID_ARGUMENTS;
    }

    return couchstore_get_default_file_ops()->close(errinfo, file->handle);
}

ssize_t TrackingFileOps::pread(couchstore_error_info_t* errinfo,
                               couch_file_handle handle,
                               void* buf,
                               size_t nbytes,
                               cs_off_t offset) {
    auto* file = reinterpret_cast<File*>(handle);
    file->recordAccess(offset, nbytes);
    return couchstore_get_default_file_ops()->pread(
            errinfo, file->handle, buf, nbytes, offset);
}

ssize_t TrackingFileOps::pwrite(couchstore_error_info_t* errinfo,
                                couch_file_handle handle,
                                const void* buf,
                                size_t nbytes,
                                cs_off_t offset) {
    auto* file = reinterpret_cast<File*>(handle);
    return couchstore_get_default_file_ops()->pwrite(
            errinfo, file->handle, buf, nbytes, offset);
}

cs_off_t TrackingFileOps::goto_eof(couchstore_error_info_t* errinfo,
                                   couch_file_handle handle) {
    auto* file = reinterpret_cast<File*>(handle);
    return couchstore_get_default_file_ops()->goto_eof(errinfo, file->handle);
}

couchstore_error_t TrackingFileOps::sync(couchstore_error_info_t* errinfo,
                                         couch_file_handle handle) {
    auto* file = reinterpret_cast<File*>(handle);
    return couchstore_get_default_file_ops()->sync(errinfo, file->handle);
}

couchstore_error_t TrackingFileOps::advise(couchstore_error_info_t* errinfo,
                                           couch_file_handle handle,
                                           cs_off_t offset,
                                           cs_off_t len,
                                           couchstore_file_advice_t advice) {
    auto* file = reinterpret_cast<File*>(handle);
    return couchstore_get_default_file_ops()->advise(
            errinfo, file->handle, offset, len, advice);
}

void TrackingFileOps::tag(couch_file_handle handle, FileTag tag) {
    auto* file = reinterpret_cast<File*>(handle);
    file->setCurrentTag(tag);
}

void TrackingFileOps::destructor(couch_file_handle handle) {
    auto* file = reinterpret_cast<File*>(handle);
    delete file;
}

TrackingFileOps::File::File(couchstore_error_info_t* errinfo)
    : handle(couchstore_get_default_file_ops()->constructor(errinfo)) {
}

TrackingFileOps::File::~File() {
    for (size_t id = 0; id < blockInfo.size(); id++) {
        if (id % 64 == 0) {
            printf("\n%10" PRIu64 "  ", uint64_t(id * blockSize));
        }
        auto& info = blockInfo.at(id);
        printf("%s", info.to_string().c_str());
    }
    printf("\n\n");

    // Print legend
    printf("\t%s     Unoccupied\n",
           BlockInfo(BlockTag::Empty).to_string().c_str());
    printf("\t%s %s   File header\n",
           BlockInfo(BlockTag::FileHeader).to_string().c_str(),
           BlockInfo(BlockTag::FileHeader, true).to_string().c_str());
    printf("\t%s %s   B-Tree (by-sequence)\n",
           BlockInfo(BlockTag::BTreeBySequence).to_string().c_str(),
           BlockInfo(BlockTag::BTreeBySequence, true).to_string().c_str());
    printf("\t%s %s   B-Tree (by-id)\n",
           BlockInfo(BlockTag::BTreeById).to_string().c_str(),
           BlockInfo(BlockTag::BTreeById, true).to_string().c_str());
    printf("\t%s %s   B-Tree (local)\n",
           BlockInfo(BlockTag::BTreeByLocal).to_string().c_str(),
           BlockInfo(BlockTag::BTreeByLocal, true).to_string().c_str());
    printf("\t%s %s   Document\n",
           BlockInfo(BlockTag::Document).to_string().c_str(),
           BlockInfo(BlockTag::Document, true).to_string().c_str());
    printf("\tlowercase: partial block occupied\n"
           "\tUppercase: whole block occupied.\n");
    printf("\tShaded background - historic (old) data.");

    couchstore_get_default_file_ops()->destructor(handle);
}

TrackingFileOps::File::BlockTag TrackingFileOps::File::encodeTag(
        FileTag currentTag, TrackingFileOps::Tree currentTree) {
    switch (currentTag) {
    case FileTag::Empty:
        return BlockTag::Empty;
    case FileTag::FileHeader:
        return BlockTag::FileHeader;
    case FileTag::BTree:
        switch (currentTree) {
        case Tree::Unknown:
            return BlockTag::Unknown;
        case Tree::Sequence:
            return BlockTag::BTreeBySequence;
        case Tree::Id:
            return BlockTag::BTreeById;
        case Tree::Local:
            return BlockTag::BTreeByLocal;
        }
    case FileTag::Document:
        return BlockTag::Document;
    case FileTag::Unknown:
        return BlockTag::Unknown;
    }
    throw std::invalid_argument(
            "TrackingFileOps::File::encodeTag: Invalid currentTag:" +
            std::to_string(int(currentTag)) + " / currentTree:" +
            std::to_string(int(currentTree)));
}

void TrackingFileOps::File::recordAccess(cs_off_t offset, size_t size) {
    // Derive our BlockTag from FileTag and BTree.
    auto blockTag = encodeTag(currentTag, currentTree);

    // Calculate the start & end block number.
    const size_t startBlkId = offset / blockSize;
    const size_t endBlkId = (offset + size) / blockSize;

    // Ensure the vector has capacity.
    if (endBlkId + 1 > blockInfo.size()) {
        blockInfo.resize(endBlkId + 1);
    }

    // For each block accessed, calculate the number of bytes accessed. If this
    // is greater than any existing tag extent, re-tag with current tag.
    for (size_t id = startBlkId; id <= endBlkId; id++) {
        // Calculate the extent of the access within this block.
        size_t blockOffset = offset % blockSize;
        const size_t accessSize = std::min(blockSize - blockOffset, size);
        auto& block = blockInfo.at(id);

        // Skip if the existing tag is historic and this one isn't -
        // we want to prioritise non-historic accesses.
        if (currentHistoric &&
            (!block.historic && (block.tag != BlockTag::Empty))) {
            continue;
        }

        // If this access size exceeds current size, tag.  If not
        // already marked as something, tag.
        if (accessSize > block.accessSize) {
            // If the tag is the same, accumulate the access size, otherwise
            // replace it.
            if (block.tag == blockTag && block.historic == currentHistoric) {
                block.accessSize += accessSize;
            } else {
                block.accessSize = accessSize;
            }
            block.tag = blockTag;
            block.historic = currentHistoric;
        }

        // After first block, offset must be zero (we will read from the start
        // of any subsequent blocks).
        offset = 0;
        // After first block; update remaining size.
        size -= accessSize;
    }
}

std::string TrackingFileOps::File::to_string(
        TrackingFileOps::File::BlockTag tag) {
    switch (tag) {
    case BlockTag::Empty:
        return "Empty";
    case BlockTag::FileHeader:
        return "FileHeader";
    case BlockTag::BTreeById:
        return "BTreeById";
    case BlockTag::BTreeBySequence:
        return "BTreeBySequence";
    case BlockTag::BTreeByLocal:
        return "BTreeByLocal";
    case BlockTag::Document:
        return "Document";
    case BlockTag::Unknown:
        return "Unknown";
    }
    throw std::invalid_argument(
            "TrackingFileOps::File::to_string: Invalid tag:" +
            std::to_string(int(tag)));
}

std::string TrackingFileOps::File::BlockInfo::to_string() {
    std::string color;
    if (historic) {
        color = ANSI_256COLOR_BG_GREY;
    }

    // Set foreground color:
    switch (tag) {
    case BlockTag::Empty:
    case BlockTag::Unknown:
        break;
    case BlockTag::FileHeader:
        color += ANSI_COLOR_RED;
        break;
    case BlockTag::BTreeById:
        color += ANSI_COLOR_YELLOW;
        break;
    case BlockTag::BTreeBySequence:
        color += ANSI_COLOR_GREEN;
        break;
    case BlockTag::BTreeByLocal:
        color += ANSI_COLOR_MAGENTA;
        break;
    case BlockTag::Document:
        color += ANSI_COLOR_BLUE;
        break;
    }

    // Set symbol.
    char symbol = 'X';
    switch (tag) {
    case BlockTag::Empty:
        symbol = '.';
        break;
    case BlockTag::FileHeader:
        symbol = 'h';
        break;
    case BlockTag::BTreeById:
    case BlockTag::BTreeBySequence:
    case BlockTag::BTreeByLocal:
        symbol = 't';
        break;
    case BlockTag::Document:
        symbol = 'd';
        break;
    case BlockTag::Unknown:
        symbol = '?';
        break;
    }
    if (isFull()) {
        symbol = std::toupper(symbol);
    }

    return color + symbol + ANSI_COLOR_RESET;
}

void TrackingFileOps::setTree(couch_file_handle handle, Tree tree) {
    auto* file = reinterpret_cast<File*>(handle);
    file->setCurrentTree(tree);
}

void TrackingFileOps::setHistoricData(couch_file_handle handle, bool historic) {
    auto* file = reinterpret_cast<File*>(handle);
    file->setHistoricData(historic);
}
