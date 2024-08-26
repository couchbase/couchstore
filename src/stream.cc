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

    bool read(gsl::span<char> buffer) override;

    void write(std::string_view buffer) override;

    void flush() override;

    void seek_begin() override;

    void seek_end() override;

private:
    FILE* file;
};

/**
 * Stream implementation which reads/writes encrypted chunks to an underlying
 * stream.
 *
 * Overwriting data may result in corrupted chunks, hence writes should be done
 * only to the end of the file.
 */
class EncryptedStream : public Stream {
public:
    EncryptedStream(std::unique_ptr<Stream> underlying,
                    std::shared_ptr<cb::crypto::SymmetricCipher> cipher,
                    size_t max_write_buffer)
        : underlying(std::move(underlying)),
          cipher(std::move(cipher)),
          max_write_buffer(max_write_buffer),
          min_chunk_size(
                  // The ciphertext should encode at least one plaintext byte,
                  // i.e. empty chunks are not allowed.
                  this->cipher->getNonceSize() + this->cipher->getMacSize() +
                  1) {
        Expects(this->underlying);
        Expects(this->cipher);
        Expects(max_write_buffer > 0);
        write_buffer.reserve(max_write_buffer);
    }

    bool read(gsl::span<char> buffer) override;

    void write(std::string_view buffer) override;

    void flush() override;

    void seek_begin() override;

    void seek_end() override;

private:
    std::unique_ptr<Stream> underlying;
    std::shared_ptr<cb::crypto::SymmetricCipher> cipher;
    std::string write_buffer;
    std::string read_buffer;
    size_t read_buffer_pos = 0;
    const size_t max_write_buffer;
    const size_t min_chunk_size;
};

std::unique_ptr<Stream> make_file_stream(const std::filesystem::path& path,
                                         const char* mode) {
    return std::make_unique<FileStream>(path.string().c_str(), mode);
}

std::unique_ptr<Stream> make_encrypted_stream(
        std::unique_ptr<Stream> underlying,
        std::shared_ptr<cb::crypto::SymmetricCipher> cipher,
        size_t buffer_size) {
    return std::make_unique<EncryptedStream>(
            std::move(underlying), std::move(cipher), buffer_size);
}

bool FileStream::read(gsl::span<char> buffer) {
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

bool EncryptedStream::read(gsl::span<char> buffer) {
    // A non-empty write buffer implies that we haven't flushed (or seeked).
    // Flushing here could overwrite chunks and corrupt the file.
    // The user would be expected to seek to the beginning of the file before
    // reading if writes were made (can't read from the end).
    Expects(write_buffer.empty());
    std::string buf;
    while (!buffer.empty()) {
        Expects(read_buffer_pos <= read_buffer.size());
        auto to_copy =
                std::min(buffer.size(), read_buffer.size() - read_buffer_pos);
        if (to_copy == 0) {
            uint32_t cipher_len;
            if (!underlying->read({reinterpret_cast<char*>(&cipher_len),
                                   sizeof(cipher_len)})) {
                return false;
            }
            cipher_len = ntohl(cipher_len);
            if (cipher_len < min_chunk_size) {
                throw Exception(COUCHSTORE_ERROR_CORRUPT,
                                "cb::couchstore::EncryptedStream::read() "
                                "cipher_len < min_chunk_size");
            }
            buf.resize(cipher_len);
            if (!underlying->read(buf)) {
                throw Exception(COUCHSTORE_ERROR_READ,
                                "cb::couchstore::EncryptedStream::read() "
                                "EOF when reading ciphertext");
            }
            read_buffer = cipher->decrypt(buf);
            read_buffer_pos = 0;
            continue;
        }
        auto begin = read_buffer.data() + read_buffer_pos;
        std::copy(begin, begin + to_copy, buffer.begin());
        buffer = {buffer.data() + to_copy, buffer.size() - to_copy};
        read_buffer_pos += to_copy;
    }
    return true;
}

void EncryptedStream::write(std::string_view buffer) {
    while (!buffer.empty()) {
        Expects(write_buffer.size() <= max_write_buffer);
        auto to_copy =
                std::min(buffer.size(), max_write_buffer - write_buffer.size());
        if (to_copy == 0) {
            flush();
            continue;
        }
        write_buffer += std::string_view(buffer.data(), to_copy);
        buffer.remove_prefix(to_copy);
    }
}

void EncryptedStream::flush() {
    read_buffer.clear();
    read_buffer_pos = 0;
    if (write_buffer.empty()) {
        return;
    }
    auto encrypted = cipher->encrypt(write_buffer);
    uint32_t cipher_len = htonl(encrypted.size());
    underlying->write(
            {reinterpret_cast<char*>(&cipher_len), sizeof(cipher_len)});
    underlying->write(encrypted);
    underlying->flush();
    write_buffer.clear();
}

void EncryptedStream::seek_begin() {
    flush();
    underlying->seek_begin();
}

void EncryptedStream::seek_end() {
    flush();
    underlying->seek_end();
}

} // namespace cb::couchstore
