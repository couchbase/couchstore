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

#include <libcouchstore/couch_db.h>

#include <gsl/gsl-lite.hpp>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>

namespace cb::crypto {
class SymmetricCipher;
}

namespace cb::couchstore {

/**
 * Provides access to a sequence of bytes (a file).
 */
class Stream {
public:
    /**
     * Reads bytes into the buffer.
     * @return false on EOF
     */
    virtual bool read(std::span<char> buffer) = 0;

    /**
     * Writes the contents of the buffer.
     */
    virtual void write(std::string_view buffer) = 0;

    /**
     * Writes the buffered bytes to the underlying file.
     */
    virtual void flush() = 0;

    /**
     * Seeks to the beginning of the file.
     */
    virtual void seek_begin() = 0;

    /**
     * Seeks to the end of the file.
     */
    virtual void seek_end() = 0;

    /**
     * Closes the file and destroys the stream.
     */
    virtual ~Stream() = default;
};

/**
 * Constructs a stream of a file.
 *
 * @param path File path
 * @param mode File open mode to be passed to fopen()
 */
std::unique_ptr<Stream> make_file_stream(const std::filesystem::path& path,
                                         const char* mode);

/**
 * Constructs a stream of a file using FileOpsInterface.
 *
 * @param path File path
 * @param errinfo Storage for system error code
 * @param ops FileOpsInterface to use
 * @param oflags File open flags
 */
std::unique_ptr<Stream> make_fileops_stream(const std::filesystem::path& path,
                                            couchstore_error_info_t& errinfo,
                                            FileOpsInterface& ops,
                                            int oflags);

/**
 * Constructs a stream that checksums data and uses an underlying stream.
 *
 * Overwriting existing data may produce a corrupted file.
 *
 * @param underlying The underlying stream to use
 * @param max_write_buffer Maximum data to buffer before checksum
 */
std::unique_ptr<Stream> make_checksum_stream(std::unique_ptr<Stream> underlying,
                                             size_t max_write_buffer = 0x10000);

/**
 * Constructs a stream that encrypts data and uses an underlying stream.
 *
 * Overwriting existing data may produce a corrupted file.
 *
 * @param underlying The underlying stream to use
 * @param cipher Encryption cipher to use
 * @param max_write_buffer Maximum plaintext to buffer before encrypting
 */
std::unique_ptr<Stream> make_encrypted_stream(
        std::unique_ptr<Stream> underlying,
        std::shared_ptr<cb::crypto::SymmetricCipher> cipher,
        size_t max_write_buffer = 0x10000);

} // namespace cb::couchstore
