/*
 *     Copyright 2024-Present Couchbase, Inc.
 *
 *   Use of this software is governed by the Business Source License included
 *   in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
 *   in that file, in accordance with the Business Source License, use of this
 *   software will be governed by the Apache License, Version 2.0, included in
 *   the file licenses/APL2.txt.
 */

#include "stream.h"
#include "couchstore_config.h" // htonl

#include "crc32.h"
#include "exception.h"
#include <cbcrypto/symmetric.h>

#include <fmt/format.h>
#include <cstdio>
#include <system_error>

namespace cb::couchstore {

/**
 * Stream implementation which uses the C FILE API to read/write data to a file.
 */
class FileStream : public Stream {
public:
    FileStream(const char* path, const char* mode) : file(fopen(path, mode)) {
        if (!file) {
            throw std::system_error(
                    errno,
                    std::generic_category(),
                    fmt::format("cb::couchstore::FileStream({})", path));
        }
    }

    ~FileStream() override {
        if (file) {
            fclose(file);
        }
    }

    bool read(std::span<char> buffer) override;

    void write(std::string_view buffer) override;

    void flush() override;

    void seek_begin() override;

    void seek_end() override;

private:
    FILE* file;
};

/**
 * Base class for streams which read/write data in chunks to an underlying
 * stream.
 */
class ChunkedStream : public Stream {
public:
    ChunkedStream(std::unique_ptr<Stream> underlying, size_t max_write_buffer)
        : underlying(std::move(underlying)),
          max_write_buffer(max_write_buffer) {
        Expects(this->underlying);
        Expects(max_write_buffer > 0);
        chunk.reserve(max_write_buffer + 32);
    }

    bool read(std::span<char> buffer) final;

    void write(std::string_view buffer) final;

    void flush() final;

    void seek_begin() final;

    void seek_end() final;

protected:
    virtual bool read_chunk() = 0;

    virtual void write_chunk() = 0;

    std::unique_ptr<Stream> underlying;
    std::string chunk;

private:
    ssize_t read_pos = 0;
    const size_t max_write_buffer;
};

/**
 * Stream implementation which reads/writes chunks with checksum to an
 * underlying stream.
 *
 * Overwriting data may result in corrupted chunks, hence writes should be done
 * only to the end of the file.
 */
class ChecksumStream final : public ChunkedStream {
public:
    ChecksumStream(std::unique_ptr<Stream> underlying, size_t max_write_buffer)
        : ChunkedStream(std::move(underlying), max_write_buffer) {
    }

private:
    struct Header {
        uint32_t length;
        uint32_t checksum;
    };

    bool read_chunk() override;

    void write_chunk() override;
};

/**
 * Stream implementation which reads/writes encrypted chunks to an underlying
 * stream.
 *
 * Overwriting data may result in corrupted chunks, hence writes should be done
 * only to the end of the file.
 */
class EncryptedStream final : public ChunkedStream {
public:
    EncryptedStream(std::unique_ptr<Stream> underlying,
                    std::shared_ptr<cb::crypto::SymmetricCipher> cipher,
                    size_t max_write_buffer)
        : ChunkedStream(std::move(underlying), max_write_buffer),
          cipher(std::move(cipher)),
          min_chunk_size(
                  // The ciphertext should encode at least one plaintext byte,
                  // i.e. empty chunks are not allowed.
                  this->cipher->getNonceSize() + this->cipher->getMacSize() +
                  1) {
    }

private:
    bool read_chunk() override;

    void write_chunk() override;

    std::shared_ptr<cb::crypto::SymmetricCipher> cipher;
    const size_t min_chunk_size;
};

std::unique_ptr<Stream> make_file_stream(const std::filesystem::path& path,
                                         const char* mode) {
    return std::make_unique<FileStream>(path.string().c_str(), mode);
}

std::unique_ptr<Stream> make_checksum_stream(std::unique_ptr<Stream> underlying,
                                             size_t buffer_size) {
    return std::make_unique<ChecksumStream>(std::move(underlying), buffer_size);
}

std::unique_ptr<Stream> make_encrypted_stream(
        std::unique_ptr<Stream> underlying,
        std::shared_ptr<cb::crypto::SymmetricCipher> cipher,
        size_t buffer_size) {
    return std::make_unique<EncryptedStream>(
            std::move(underlying), std::move(cipher), buffer_size);
}

bool FileStream::read(std::span<char> buffer) {
    if (fread(buffer.data(), buffer.size(), 1, file) != 1) {
        if (feof(file)) {
            return false;
        }
        throw std::system_error(errno,
                                std::generic_category(),
                                "cb::couchstore::FileStream::read");
    }
    return true;
}

void FileStream::write(std::string_view buffer) {
    if (fwrite(buffer.data(), buffer.size(), 1, file) != 1) {
        throw std::system_error(errno,
                                std::generic_category(),
                                "cb::couchstore::FileStream::write");
    }
}

void FileStream::flush() {
    if (fflush(file) != 0) {
        throw std::system_error(errno,
                                std::generic_category(),
                                "cb::couchstore::FileStream::flush");
    }
}

void FileStream::seek_begin() {
    errno = 0;
    rewind(file);
    if (errno) {
        throw std::system_error(errno,
                                std::generic_category(),
                                "cb::couchstore::FileStream::seek_begin");
    }
}

void FileStream::seek_end() {
    if (fseek(file, 0, SEEK_END) != 0) {
        throw std::system_error(errno,
                                std::generic_category(),
                                "cb::couchstore::FileStream::seek_end");
    }
}

bool ChunkedStream::read(std::span<char> buffer) {
    if (read_pos < 0) {
        // A dirty buffer implies that we haven't flushed (or seeked).
        // Flushing here could overwrite chunks and corrupt the file.
        // The user would be expected to seek to the beginning of the file
        // before reading if writes were made (can't read from the end).
        throw std::logic_error(
                "cb::couchstore::ChunkedStream::read with dirty buffer");
    }
    while (!buffer.empty()) {
        Expects(static_cast<size_t>(read_pos) <= chunk.size());
        auto to_copy = std::min(buffer.size(), chunk.size() - read_pos);
        if (to_copy == 0) {
            if (!read_chunk()) {
                return false;
            }
            read_pos = 0;
            continue;
        }
        auto begin = chunk.data() + read_pos;
        std::copy(begin, begin + to_copy, buffer.data());
        buffer = {buffer.data() + to_copy, buffer.size() - to_copy};
        read_pos += to_copy;
    }
    return true;
}

void ChunkedStream::write(std::string_view buffer) {
    if (read_pos >= 0) {
        chunk.clear();
        read_pos = -1;
    }
    while (!buffer.empty()) {
        Expects(chunk.size() <= max_write_buffer);
        auto to_copy = std::min(buffer.size(), max_write_buffer - chunk.size());
        if (to_copy == 0) {
            write_chunk();
            chunk.clear();
            continue;
        }
        chunk.append(buffer.data(), to_copy);
        buffer.remove_prefix(to_copy);
    }
}

void ChunkedStream::flush() {
    if (read_pos < 0 && !chunk.empty()) {
        write_chunk();
    }
    chunk.clear();
    read_pos = 0;
    underlying->flush();
}

void ChunkedStream::seek_begin() {
    flush();
    underlying->seek_begin();
}

void ChunkedStream::seek_end() {
    flush();
    underlying->seek_end();
}

bool ChecksumStream::read_chunk() {
    Header header;
    if (!underlying->read({reinterpret_cast<char*>(&header), sizeof(header)})) {
        return false;
    }
    header.length = ntohl(header.length);
    header.checksum = ntohl(header.checksum);
    if (header.length < sizeof(uint32_t)) {
        throw Exception(COUCHSTORE_ERROR_CORRUPT,
                        "cb::couchstore::ChecksumStream::read() "
                        "Check length too small");
    }
    chunk.resize(header.length - sizeof(uint32_t));
    if (!underlying->read(chunk)) {
        throw Exception(COUCHSTORE_ERROR_READ,
                        "cb::couchstore::ChecksumStream::read() "
                        "EOF when reading chunk");
    }
    if (!perform_integrity_check(reinterpret_cast<uint8_t*>(chunk.data()),
                                 chunk.size(),
                                 header.checksum,
                                 CRC32C)) {
        throw Exception(COUCHSTORE_ERROR_CHECKSUM_FAIL,
                        "cb::couchstore::ChecksumStream::read() "
                        "Invalid checksum");
    }
    return true;
}

void ChecksumStream::write_chunk() {
    Header header;
    header.length = chunk.size() + sizeof(uint32_t);
    header.checksum = get_checksum(
            reinterpret_cast<uint8_t*>(chunk.data()), chunk.size(), CRC32C);
    header.length = htonl(header.length);
    header.checksum = htonl(header.checksum);
    underlying->write({reinterpret_cast<char*>(&header), sizeof(header)});
    underlying->write(chunk);
}

bool EncryptedStream::read_chunk() {
    uint32_t cipher_len;
    if (!underlying->read(
                {reinterpret_cast<char*>(&cipher_len), sizeof(cipher_len)})) {
        return false;
    }
    cipher_len = ntohl(cipher_len);
    if (cipher_len < min_chunk_size) {
        throw Exception(COUCHSTORE_ERROR_CORRUPT,
                        "cb::couchstore::EncryptedStream::read() "
                        "cipher_len < min_chunk_size");
    }
    chunk.resize(cipher_len);
    if (!underlying->read(chunk)) {
        throw Exception(COUCHSTORE_ERROR_READ,
                        "cb::couchstore::EncryptedStream::read() "
                        "EOF when reading ciphertext");
    }
    chunk = cipher->decrypt(chunk);
    return true;
}

void EncryptedStream::write_chunk() {
    if (chunk.empty()) {
        return;
    }
    auto encrypted = cipher->encrypt(chunk);
    uint32_t cipher_len = htonl(encrypted.size());
    underlying->write(
            {reinterpret_cast<char*>(&cipher_len), sizeof(cipher_len)});
    underlying->write(encrypted);
}

} // namespace cb::couchstore
