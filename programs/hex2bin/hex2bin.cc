// Alternative to `xxd` suitable for investigating partial hexdumps.
// `xxd -r` fills missing regions with zeros, which makes it hard to
// distinguish from real regions filled with zeros. `xxd` also treats
// multibyte values as big-endian, while `hexdump` as little-endian.

#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

static unsigned long long unhex(const char** ptr) {
    auto str = *ptr;
    unsigned long long value = 0;
    for (;;) {
        auto ch = *str;
        if (ch >= '0' && ch <= '9') {
            value = (value << 4) | (ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            value = (value << 4) | (ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            value = (value << 4) | (ch - 'A' + 10);
        } else {
            *ptr = str;
            return value;
        }
        ++str;
    }
}

int main(int argc, char**) {
    if (argc != 1) {
        std::cerr << "Decodes hexdump output, replacing any missing region "
                     "with '?' characters.\n";
        return 1;
    }
    std::string line;
    std::vector<unsigned char> chunk;
    unsigned long long pos = 0;
    bool repeat = false;
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            break;
        }
        const char* str = line.c_str();
        if (*str == '*') {
            repeat = true;
            continue;
        }
        auto old_str = str;
        auto offset = unhex(&str);
        if (str == old_str) {
            break;
        }
        if (repeat && !chunk.empty()) {
            while (pos < offset) {
                if (fwrite(chunk.data(), chunk.size(), 1, stdout) != 1) {
                    return 2;
                }
                pos += chunk.size();
            }
        } else {
            while (pos < offset) {
                if (putchar('?') == EOF) {
                    return 2;
                }
                ++pos;
            }
        }
        repeat = false;
        chunk.clear();
        for (;;) {
            while (*str == ' ') {
                ++str;
            }
            old_str = str;
            auto value = unhex(&str);
            if (str == old_str) {
                break;
            }
            // hexdump can output multibyte values, which are little-endian
            std::size_t num_bytes = str - old_str;
            num_bytes /= 2;
            while (num_bytes--) {
                chunk.push_back(static_cast<unsigned char>(value));
                value >>= 8;
            }
        }
        if (chunk.empty()) {
            continue;
        }
        if (fwrite(chunk.data(), chunk.size(), 1, stdout) != 1) {
            return 2;
        }
        pos += chunk.size();
    }
    if (fflush(stdout) == EOF) {
        return 2;
    }
    return 0;
}
